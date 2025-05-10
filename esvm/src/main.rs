extern crate chrono;
extern crate clap;
extern crate esvm;
#[macro_use]
extern crate log;
extern crate fern;
extern crate num_cpus;
extern crate yaml_rust;

#[macro_use]
extern crate serde_json;

use std::env;
use std::fs::{self, File};
use std::io::Read;

use clap::{App, Arg, ArgMatches};
use yaml_rust::YamlLoader;

use esvm::{symbolic_analysis, SeEnviroment, Solvers, CONFIG};

fn init_logger(json_mode: bool) -> Result<(), fern::InitError> {
    fs::create_dir_all("log")?;
    let level = match env::var_os("RUST_LOG") {
        Some(level) => match level.to_str().unwrap() {
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "trace" => log::LevelFilter::Trace,
            _ => panic!("Declared invalid logging level!"),
        },
        None => log::LevelFilter::Info,
    };
    let mut builder = fern::Dispatch::new()
        // Perform allocation-free log formatting
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        // Add blanket level filter -
        .level(level)
        // allways log to log file
        .chain(fern::log_file("log/evmse.log")?);
    if !json_mode {
        builder = builder.chain(std::io::stdout());
    }

    builder.apply()?;
    Ok(())
}

pub fn main() {
    // init logger
    let matches = parse_args();
    init_logger(matches.is_present("json")).expect("Could not initialize logger");
    analysis(matches);
}

fn analysis(matches: ArgMatches) {
    // block people from being dumb
    assert!(
        !(matches.is_present("all_optimizations") && matches.is_present("disable_optimizations"))
    );

    esvm::set_global_config(&matches);
    single_analysis(matches);
}

fn single_analysis(matches: clap::ArgMatches) {
    let se_env;
    let input = matches.value_of("INPUT").unwrap();
    let mut f = File::open(input).unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    let yaml = YamlLoader::load_from_str(&s).unwrap();
    se_env = SeEnviroment::from_yaml(&yaml[0]);

    let config = CONFIG.read().unwrap().clone();

    let pool = if let Some(solver) = matches.value_of("solver") {
        match solver {
            "z3" => Solvers::Z3 {
                count: CONFIG.read().unwrap().cores,
                timeout: CONFIG.read().unwrap().solver_timeout,
            },
            "boolector" => Solvers::Boolector {
                count: CONFIG.read().unwrap().cores,
                timeout: CONFIG.read().unwrap().solver_timeout,
            },
            "yice" => Solvers::Yice {
                count: CONFIG.read().unwrap().cores,
                timeout: CONFIG.read().unwrap().solver_timeout,
            },
            _ => panic!("Supplied incorrect solver name"),
        }
    } else {
        Solvers::Yice {
            count: CONFIG.read().unwrap().cores,
            timeout: CONFIG.read().unwrap().solver_timeout,
        }
    };

    let res = symbolic_analysis(se_env, config, pool);
    if matches.is_present("json") {
        println!("{}", json!(res));
    } else {
        for l in format!("{}", res).lines() {
            info!("{}", l);
        }
    }
}

fn parse_args<'a>() -> ArgMatches<'a> {
    let app = App::new("EthBMC")
        .version("1.0.0")
        .about("EthBMC: A Bounded Model Checker for Smart Contracts")
        // General
        .arg(
            Arg::with_name("INPUT")
                .help("Set input file")
                .required(true)
                .index(1),
        )
        .arg(Arg::with_name("json").long("json").help("Output json without logging"))
        .arg(Arg::with_name("solver").long("solver").takes_value(true).help("The SMT solver to use: z3, boolector, yices2 [yices2]"));
    let app = esvm::arguments(app);
    app.get_matches()
}
