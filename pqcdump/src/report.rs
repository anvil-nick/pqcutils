use rust_embed::RustEmbed;
use tera::{Context, Tera};
use std::fs::File;
use chrono::Utc;
use std::path::Path;
use crate::ReportResults;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support/templates/"]
struct EmbeddedResources;

pub fn generate_report(output_file: &Path, results: ReportResults) -> Result<(), Box<dyn std::error::Error>>
{
    let templates = [
        "macros.html",
        "template.html",
        "ssh_results.html",
        "tls_results.html",
        "summary.html",
    ];
    let mut tera = Tera::default();

    log::debug!("Loading HTML templates");
    for template in templates {
        let html_file = EmbeddedResources::get(template)
            .ok_or_else(|| format!("Embedded template not found: {template}"))?;
        let html_data = std::str::from_utf8(html_file.data.as_ref())?;
        tera.add_raw_template(template, html_data)?;
    }

    let mut ctx = Context::from_serialize(results)?;

    let dt = Utc::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();
    ctx.insert("title", &dt);
    ctx.insert("PQC_SUPPORTED", &crate::PQC_SUPPORTED);

    log::trace!("Tera Template: {:?}", ctx);

    log::debug!("Rendering HTML report to {}", output_file.display());
    let f = File::create(output_file)?;
    tera.render_to("template.html", &ctx, f)?;
    log::info!("HTML report written to {}", output_file.display());

    Ok(())
}