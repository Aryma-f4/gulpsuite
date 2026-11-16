use gulpsuite::ui::html_preview::{html_body, render};
#[test]
fn recognises_html_without_content_type_and_bom() {
    assert!(html_body("HTTP/1.1 200 OK\r\n\r\n\u{feff}<html>ok</html>").is_some());
    assert!(
        html_body("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n<html>ok</html>").is_some()
    );
    assert!(
        html_body("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"key\":1}").is_none()
    );
}
#[test]
fn dechunked_and_wire_chunked_html_both_render() {
    let head =
        "HTTP/1.1 302 Found\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n";
    let body = "<html>redirect</html>";
    assert_eq!(html_body(&format!("{head}{body}")), Some(body.into()));
    assert_eq!(
        html_body(&format!("{head}{:x}\r\n{body}\r\n0\r\n\r\n", body.len())),
        Some(body.into())
    );
}
#[test]
#[ignore = "requires installed bundled Chromium; set GULPSUITE_TEST_CHROMIUM"]
fn chromium_preview_renders_css_javascript_and_embedded_images_without_network() {
    use base64::Engine;
    let svg=base64::engine::general_purpose::STANDARD.encode("<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100'><rect width='100' height='100' fill='rgb(20,30,230)'/></svg>");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let html=format!("<html><head><style>body{{margin:0}}div,img{{position:absolute;top:0;width:100px;height:100px}}#css{{left:0;background:rgb(230,20,30)}}#js{{left:100px;background:black}}img{{left:200px}}</style></head><body><div id='css'></div><div id='js'></div><img src='data:image/svg+xml;base64,{svg}'><img src='http://127.0.0.1:{port}/must-not-load'><script>document.getElementById('js').style.background='rgb(20,200,30)';fetch('http://127.0.0.1:{port}/must-not-fetch').catch(()=>{{}});try{{parent.document.body.innerHTML='LEAK';}}catch(e){{}}</script></body></html>");
    let executable = std::path::PathBuf::from(std::env::var_os("GULPSUITE_TEST_CHROMIUM").unwrap());
    let pixels = render(&executable, &html).unwrap();
    let pixel = |x: usize, y: usize| &pixels.rgba[(y * pixels.width + x) * 4..][..3];
    assert_eq!(
        pixel(50, 50),
        [230, 20, 30],
        "CSS must render; sandbox must deny parent DOM access"
    );
    assert_eq!(
        pixel(150, 50),
        [20, 200, 30],
        "inline JavaScript must render"
    );
    assert_eq!(pixel(250, 50), [20, 30, 230], "embedded image must render");
    assert!(
        matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock),
        "captured HTML must not contact network resources"
    );
    if let Ok(path) = std::env::var("GULPSUITE_PREVIEW_SCREENSHOT") {
        let mut encoder = png::Encoder::new(
            std::fs::File::create(path).unwrap(),
            pixels.width as u32,
            pixels.height as u32,
        );
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&pixels.rgba)
            .unwrap();
    }
}

#[test]
#[ignore = "requires installed bundled Chromium; localhost external-resource opt-in fixture"]
fn chromium_external_resources_require_opt_in_and_use_response_base_url() {
    use std::io::{BufRead, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut first = String::new();
                std::io::BufReader::new(&mut stream)
                    .read_line(&mut first)
                    .unwrap();
                assert!(
                    first.starts_with("GET /preview/style.css "),
                    "relative CSS must use response URL: {first}"
                );
                let css = "body{margin:0;background:rgb(40,80,160)}";
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{css}",css.len()).unwrap();
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "external resource was not requested after opt-in"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    });
    let executable = std::path::PathBuf::from(std::env::var_os("GULPSUITE_TEST_CHROMIUM").unwrap());
    let pixels=gulpsuite::ui::html_preview::render_with_options(&executable,"<!doctype html><html><head><link rel='stylesheet' href='style.css'></head><body>Relative resource fixture</body></html>",true,Some(&format!("http://127.0.0.1:{port}/preview/index.html"))).unwrap();
    server.join().unwrap();
    let offset = (200 * pixels.width + 200) * 4;
    assert_eq!(&pixels.rgba[offset..offset + 3], &[40, 80, 160]);
}
