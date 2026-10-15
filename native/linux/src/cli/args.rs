//! Strict command shapes. Parsing performs no filesystem or endpoint I/O.
use jocky_shared::collection::Code;

pub(crate) enum Command {
    Help,
    Version,
    Validate {
        required: [String; 4],
        indicators: Option<String>,
    },
    VerifyReport(String),
    WorkerDirect,
    Collect {
        required: [String; 4],
        indicators: Option<String>,
        output: String,
    },
}

pub(crate) fn parse(args: &[String]) -> Result<Command, Code> {
    match args {
        [flag] if flag == "--help" => return Ok(Command::Help),
        [flag] if flag == "--version" => return Ok(Command::Version),
        [command, path] if command == "verify-report" => {
            return Ok(Command::VerifyReport(path.clone()));
        }
        [command] if command == "__worker" => {
            return Ok(Command::WorkerDirect);
        }
        [command, rest @ ..] if command == "validate-inputs" => {
            if rest.len() < 8 || rest.len() > 10 || rest.len() % 2 != 0 {
                return Err(Code::InvalidInput);
            }
            let mut slots: [Option<String>; 5] = std::array::from_fn(|_| None);
            for pair in rest.as_chunks::<2>().0 {
                let index = match pair[0].as_str() {
                    "--designation" => 0,
                    "--authorisation" => 1,
                    "--policy" => 2,
                    "--request" => 3,
                    "--indicators" => 4,
                    _ => return Err(Code::InvalidInput),
                };
                if slots[index].replace(pair[1].clone()).is_some() {
                    return Err(Code::InvalidInput);
                }
            }
            let [
                Some(designation),
                Some(authorisation),
                Some(policy),
                Some(request),
                indicators,
            ] = slots
            else {
                return Err(Code::InvalidInput);
            };
            return Ok(Command::Validate {
                required: [designation, authorisation, policy, request],
                indicators,
            });
        }
        [command, rest @ ..] if command == "collect" => {
            if rest.len() < 11 || rest.len() > 13 || (rest.len() - 1) % 2 != 0 {
                return Err(Code::InvalidInput);
            }
            let mut slots: [Option<String>; 6] = std::array::from_fn(|_| None);
            let mut opted_in = false;
            let mut index = 0;
            while index < rest.len() {
                if rest[index] == "--allow-live-lab" {
                    if opted_in {
                        return Err(Code::InvalidInput);
                    }
                    opted_in = true;
                    index += 1;
                    continue;
                }
                let [flag, value] = rest.get(index..index + 2).ok_or(Code::InvalidInput)? else {
                    return Err(Code::InvalidInput);
                };
                let slot = match flag.as_str() {
                    "--designation" => 0,
                    "--authorisation" => 1,
                    "--policy" => 2,
                    "--request" => 3,
                    "--indicators" => 4,
                    "--output" => 5,
                    _ => return Err(Code::InvalidInput),
                };
                if value.starts_with("--") || slots[slot].replace(value.clone()).is_some() {
                    return Err(Code::InvalidInput);
                }
                index += 2;
            }
            if !opted_in {
                return Err(Code::InvalidInput);
            }
            let [
                Some(designation),
                Some(authorisation),
                Some(policy),
                Some(request),
                indicators,
                Some(output),
            ] = slots
            else {
                return Err(Code::InvalidInput);
            };
            return Ok(Command::Collect {
                required: [designation, authorisation, policy, request],
                indicators,
                output,
            });
        }
        _ => {}
    }
    Err(Code::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_unknown_and_incomplete_options_fail_without_io() {
        for args in [
            vec!["validate-inputs", "--designation", "/a"],
            vec![
                "validate-inputs",
                "--designation",
                "/a",
                "--designation",
                "/b",
                "--policy",
                "/c",
                "--request",
                "/d",
            ],
            vec![
                "validate-inputs",
                "--designation",
                "/a",
                "--authorisation",
                "/b",
                "--policy",
                "/c",
                "--unknown",
                "/d",
            ],
            vec!["verify-report"],
            vec!["--help", "extra"],
        ] {
            assert!(matches!(
                parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()),
                Err(Code::InvalidInput)
            ));
        }
    }
}
