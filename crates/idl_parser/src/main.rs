// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: idl_parser <file.idl>");
        std::process::exit(2);
    };

    match parse_path(Path::new(&path)) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn parse_path(path: &Path) -> Result<String, String> {
    let ast = idl_parser::parse_idl_file(path).map_err(|error| error.to_string())?;
    Ok(format!("{} declarations", ast.declarations.len()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn parse_path_reports_declaration_count() {
        let root =
            std::env::temp_dir().join(format!("govfuzz-idl-parser-{}-summary", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create fixture dir");
        fs::write(root.join("common.idl"), "interface Common {};\n").expect("write include");
        let path = root.join("root.idl");
        fs::write(&path, "#include \"common.idl\"\ninterface Root {};").expect("write fixture");

        let summary = super::parse_path(&path).expect("fixture parses");

        fs::remove_dir_all(root).expect("remove fixture dir");
        assert_eq!(summary, "2 declarations");
    }
}
