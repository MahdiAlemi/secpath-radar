//! Minijinja HTML rendering and static asset copying.

use crate::prelude::*;

pub(crate) fn render_html(
    brief: &Value,
    template_path: &PathBuf,
    out_path: &PathBuf,
) -> Result<()> {
    let template_raw = fs::read_to_string(template_path)
        .with_context(|| format!("failed to read template: {}", template_path.display()))?;

    let mut env = Environment::new();
    env.add_template("index.html", &template_raw)
        .context("failed to register template")?;

    let tmpl = env.get_template("index.html")?;
    let rendered = tmpl.render(context!(brief => brief))?;

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory: {}", parent.display()))?;
    }

    fs::write(out_path, rendered)
        .with_context(|| format!("failed to write output HTML: {}", out_path.display()))?;
    Ok(())
}

pub(crate) fn copy_static_assets(out_path: &PathBuf) -> Result<()> {
    let Some(site_dir) = out_path.parent() else {
        return Ok(());
    };

    let src = PathBuf::from("assets");
    if !src.exists() {
        return Ok(());
    }

    let dest = site_dir.join("assets");
    copy_dir_recursive(&src, &dest)
}

pub(crate) fn copy_dir_recursive(src: &PathBuf, dest: &PathBuf) -> Result<()> {
    fs::create_dir_all(dest)
        .with_context(|| format!("failed to create asset directory: {}", dest.display()))?;

    for entry in fs::read_dir(src)
        .with_context(|| format!("failed to read asset directory: {}", src.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let target = dest.join(entry.file_name());

        if path.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else {
            fs::copy(&path, &target).with_context(|| {
                format!(
                    "failed to copy static asset from {} to {}",
                    path.display(),
                    target.display()
                )
            })?;
        }
    }

    Ok(())
}
