use ark_std::UniformRand;
use clap::{Parser, Subcommand};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{fs, path::PathBuf};
use tacita_ste_comparison::{
    benchmark::{mask_seed, run, Config, Fixture},
    ste::{wire, Gt},
};

#[derive(Parser)]
#[command(about = "TACITA STE benchmark, without MKLHTS. CPU only.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Bench {
        #[arg(long, default_value_t = 1000)]
        n_clients: usize,
        #[arg(long, default_value_t = 800)]
        active_clients: usize,
        #[arg(long, default_value_t = 50)]
        committee_size: usize,
        #[arg(long, default_value_t = 40)]
        threshold: usize,
        #[arg(long, default_value_t = 1)]
        slots: usize,
        #[arg(long, default_value_t = 32)]
        threads: usize,
        #[arg(long, default_value_t = 255)]
        input_bound: i64,
        #[arg(long)]
        unmasked_key_inputs: bool,
        #[arg(long)]
        fig7: bool,
        #[arg(long)]
        input_json: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    Seeds {
        #[arg(long)]
        fig7: bool,
        #[arg(long)]
        clients: usize,
        #[arg(long)]
        output: PathBuf,
    },
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Bench {
            n_clients,
            active_clients,
            committee_size,
            threshold,
            slots,
            threads,
            input_bound,
            unmasked_key_inputs,
            fig7,
            input_json,
            output,
        } => {
            if output.exists() {
                return Err("output exists; choose a new run directory".into());
            }
            let fixture = input_json
                .map(|p| -> Result<Fixture, Box<dyn std::error::Error>> {
                    Ok(serde_json::from_slice(&fs::read(p)?)?)
                })
                .transpose()?;
            eprintln!("starting STE: active={active_clients} committee={committee_size} threshold={threshold} slots={slots} threads={threads}");
            let config = Config {
                n_clients,
                active_clients,
                committee_size,
                threshold,
                slots,
                threads,
                input_bound,
                mask_inputs: !unmasked_key_inputs,
            };
            let report = if fig7 {
                serde_json::to_value(tacita_ste_comparison::fig7_benchmark::run(
                    config,
                    fixture.ok_or("--fig7 requires a KAHE key fixture")?,
                )?)?
            } else {
                serde_json::to_value(run(config, fixture)?)?
            };
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
            println!(
                "protocol={} active_clients={} online_wall_s={} correctness=pass",
                report["protocol"], active_clients, report["online_wall_s"]
            );
            println!("results={}", output.display());
        }
        Command::Seeds {
            clients,
            output,
            fig7,
        } => {
            if clients == 0 || output.exists() {
                return Err("clients must be positive and output must be new".into());
            }
            let mut rng = StdRng::from_entropy();
            let value = if fig7 {
                let seeds: Vec<Vec<u8>> = (0..clients)
                    .map(|_| {
                        let mut s = vec![0; 32];
                        rng.fill_bytes(&mut s);
                        s
                    })
                    .collect();
                serde_json::json!({"encoding": "uniform-32-byte-seed", "seeds": seeds, "mask_seeds": seeds})
            } else {
                let seeds: Vec<Gt> = (0..clients).map(|_| Gt::rand(&mut rng)).collect();
                serde_json::json!({"seeds": seeds.iter().map(wire).collect::<Vec<_>>(), "mask_seeds": seeds.iter().map(|x| mask_seed(*x)).collect::<Vec<_>>()})
            };
            fs::write(output, serde_json::to_vec(&value)?)?;
        }
    }
    Ok(())
}
