#[path = "src/icon.rs"]
mod icon;

use std::{env, fs::File, path::PathBuf};

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="FirewallManager" type="win32"/>
  <description>Firewall Manager</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=src/icon.rs");
    println!("cargo:rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ico_path = out_dir.join("app.ico");

    let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16u32, 20, 24, 32, 40, 48, 64, 128, 256] {
        let image = ico::IconImage::from_rgba_data(size, size, icon::render(size));
        dir.add_entry(ico::IconDirEntry::encode(&image).expect("encode icon"));
    }
    dir.write(File::create(&ico_path).expect("create ico")).expect("write ico");

    let mut res = winresource::WindowsResource::new();
    res.set_icon(ico_path.to_str().unwrap());
    res.set_manifest(MANIFEST);
    res.set("FileDescription", "Firewall Manager");
    res.set("ProductName", "Firewall Manager");
    // Only the app binary gets the admin manifest, so `cargo test` can run unelevated.
    res.compile_for("FirewallManager").expect("compile Windows resources");
}
