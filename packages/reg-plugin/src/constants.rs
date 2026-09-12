use regex::Regex;
use std::sync::LazyLock;

// Layout per https://docs.fileformat.com/executable/reg/:
//
//   RegistryEditorVersion
//   <blank line>
//   [RegistryPath1]
//   "DataItemName1"=DataType1:DataValue1
//   "DataItemName2"=DataType2:DataValue2
//   <blank line>
//   [RegistryPath2]
//   ...

pub static REGISTRY_EDITOR_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?<version>Windows Registry Editor Version \d+\.\d+|REGEDIT4)\s*$").unwrap()
});

pub static REGISTRY_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\[(?<path>[^\]]+)\]\s*$").unwrap());

pub static REGISTRY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        ^
        (?:
              " (?<name> (?: [^"\\] | \\. )* ) "   # "DataItemName"
            | (?<default> @ )                      # @ stands for the key's unnamed value
        )
        =
        (?:                                        # DataType, absent for a plain string
            (?<kind>
                  dword
                | qword
                | hex (?: \( (?<code> [0-9a-fA-F]+ ) \) )?
            )
            :
        )?
        (?<data> .* )                              # DataValue, still quoted/comma-separated
        $
    "#,
    )
    .unwrap()
});
