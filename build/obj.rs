// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
extern crate goblin;
use self::goblin::elf;
use self::goblin::mach;

use std::error;

/// List symbols exported by the file (expected to be either a static library or an object file).
pub fn exported_symbols(file: &str) -> Result<BTreeSet<String>, Box<dyn error::Error>> {
    let mut bytes = Vec::new();
    File::open(file)?.read_to_end(&mut bytes)?;
    binary_exported_symbols(&bytes)
}

fn binary_exported_symbols(bytes: &[u8]) -> Result<BTreeSet<String>, Box<dyn error::Error>> {
    let mut symbols = BTreeSet::new();
    match goblin::Object::parse(bytes)? {
        goblin::Object::Archive(archive) => {
            for (_member_name, member, _symbol_table) in archive.summarize() {
                // Member size is likely to be reported incorrectly by its header.
                assert!(
                    member.offset + (member.size() as u64) <= (bytes.len() as u64),
                    format!(
                        "archive member is outside of boundaries; offset: {}, size: {}",
                        member.offset,
                        member.size()
                    )
                );
                symbols.extend(binary_exported_symbols(
                    &bytes[member.offset as usize..member.offset as usize + member.size()],
                )?);
            }
        }
        goblin::Object::Elf(elf) => {
            for symbol in elf.syms.iter() {
                let name = elf
                    .strtab
                    .get(symbol.st_name)
                    .unwrap_or_else(|| {
                        panic!(
                            "incorrect symbol name table offset {} for: {:?}",
                            symbol.st_name, symbol
                        )
                    })
                    .expect("failed to read symbol name");
                if !name.is_empty()
                    && symbol.st_bind() != elf::sym::STB_LOCAL
                    && u32::try_from(symbol.st_shndx).unwrap() != elf::section_header::SHN_UNDEF
                {
                    symbols.insert(name.to_string());
                }
            }
        }
        goblin::Object::Mach(mach) => match mach {
            mach::Mach::Binary(obj) => {
                for symbol in obj.symbols() {
                    let (name, nlist) = symbol?;
                    if nlist.is_global() && !nlist.is_undefined() {
                        // Strip underscore symbol prefix.
                        symbols.insert(name[1..].to_string());
                    }
                }
            }
            mach::Mach::Fat(_obj) => panic!("unexpected multiarch Mach-O binary found in archive"),
        },
        // Symbols are stripped out of PE file.
        goblin::Object::PE(_pe) => panic!("unexpected PE executable found in archive"),
        // goblin::Object::parse doesn't detect COFF binaries.
        goblin::Object::Unknown(_magic) => {
            let coff = goblin::pe::Coff::parse(bytes)?;
            for (_size, _name, symbol) in coff.symbols.iter() {
                if symbol.section_number != goblin::pe::symbol::IMAGE_SYM_UNDEFINED
                    && symbol.storage_class == goblin::pe::symbol::IMAGE_SYM_CLASS_EXTERNAL
                {
                    // _name will only be populated for names no longer than 8 characters,
                    // otherwise string table lookup is necessary.
                    symbols.insert(symbol.name(&coff.strings)?.to_string());
                }
            }
        }
    };
    Ok(symbols)
}
