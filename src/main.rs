use axum::{
    body::{boxed, Full},
    extract::{DefaultBodyLimit, Extension, Multipart, Path},
    http::{HeaderValue, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use serde::Serialize;
use std::{
    net::SocketAddr,
    path::{Path as StdPath, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use tokio::fs;
use chrono::{DateTime, Local};
use tracing::{info, error};
use tracing_subscriber;
use urlencoding::encode;  // 添加导入

// 定义命令行参数结构体
#[derive(Parser)]
struct Cli {
    #[clap(long, default_value = "8080")]
    port: u16,
    #[clap(short, long, default_value = ".")]
    directory: String,
}

// 定义应用状态结构体
struct AppState {
    root_dir: PathBuf,
}

impl AppState {
    fn get_safe_path(&self, requested_path: &str) -> Result<PathBuf, (StatusCode, &'static str)> {
        let mut path = self.root_dir.clone();
        let requested_path = requested_path.trim_start_matches('/');

        // 防止路径遍历攻击
        for component in StdPath::new(requested_path).components() {
            match component {
                std::path::Component::Normal(os_str) => {
                    path.push(os_str);
                }
                _ => {
                    return Err((StatusCode::BAD_REQUEST, "无效的路径"));
                }
            }
        }

        // 获取规范路径并确保它在根目录内
        let canonical = path.canonicalize().map_err(|_| (StatusCode::BAD_REQUEST, "路径无效或不存在"))?;

        if !canonical.starts_with(&self.root_dir) {
            return Err((StatusCode::FORBIDDEN, "访问被拒绝"));
        }

        Ok(canonical)
    }
}

// 结构体用于 JSON 响应
#[derive(Serialize)]
struct UploadResponse {
    status: String,
}

#[tokio::main]
async fn main() {
    // 初始化日志记录
    tracing_subscriber::fmt::init();

    // 解析命令行参数
    let args = Cli::parse();

    // 创建共享状态
    let state = Arc::new(AppState {
        root_dir: PathBuf::from(args.directory.clone()),
    });

    // 构建路由，支持嵌套路径
    let app = Router::new()
        .route(
            "/*path",
            get(show_files).post(upload_file).delete(delete_file)
        )
        .route("/download/*path", get(download_file))
        // 添加请求体大小限制中间件，设置为 10 GB
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024 * 1024))
        // 添加共享状态
        .layer(Extension(state.clone()));

    // 定义服务器地址
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!("服务器运行在 http://{}", addr);

    // 启动服务器
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}


// 显示文件列表，并添加上传进度条和删除功能
async fn show_files(Path(path): Path<String>, Extension(state): Extension<Arc<AppState>>) -> Result<Html<String>, (StatusCode, &'static str)> {
    let safe_path = match state.get_safe_path(&path) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };

    let mut entries = fs::read_dir(&safe_path).await.map_err(|e| {
        error!("无法读取目录 {:?}: {:?}", safe_path, e);
        (StatusCode::INTERNAL_SERVER_ERROR, "无法读取目录")
    })?;
    let mut files = Vec::new();

    while let Some(entry) = entries.next_entry().await.map_err(|e| {
        error!("无法读取目录项: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "无法读取目录项")
    })? {
        let path = entry.path();
        let metadata = fs::metadata(&path).await.map_err(|e| {
            error!("无法获取文件元数据 {:?}: {:?}", path, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "无法获取文件元数据")
        })?;
        let file_name = entry.file_name().into_string().map_err(|e| {
            error!("文件名无效: {:?}", e);
            (StatusCode::BAD_REQUEST, "文件名无效")
        })?;
        let file_size = if path.is_file() { format_size(metadata.len()) } else { "-".to_string() };
        let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let datetime_modified: DateTime<Local> = DateTime::from(modified_time);
        let modified_time_str = datetime_modified.format("%Y-%m-%d %H:%M:%S").to_string();
        files.push((file_name, file_size, modified_time_str, path.is_dir()));
    }

    let file_rows = files
        .into_iter()
        .map(|(name, size, modified, is_dir)| {
            if is_dir {
                let encoded_name = encode(&name).into_owned();
                let display_name = format!("{}/", name);
                let new_path = if path.is_empty() {
                    encoded_name.clone()
                } else {
                    format!("{}/{}", encode(&path).into_owned(), encoded_name)
                };
                format!(
                    "<tr>
                        <td><a href=\"/?path={0}/\">{1}</a></td>
                        <td>{2}</td>
                        <td>{3}</td>
                        <td></td>
                        <td></td>
                    </tr>",
                    new_path,
                    display_name,
                    size,
                    modified
                )
            } else {
                let file_path = if path.is_empty() {
                    encode(&name).into_owned()
                } else {
                    let full_path = format!("{}/{}", path, name);
                    encode(&full_path).into_owned()
                };
                format!(
                    "<tr>
                        <td><a href=\"/download/{0}\">{1}</a></td>
                        <td>{2}</td>
                        <td>{3}</td>
                        <td></td>
                        <td><button class=\"delete-button\" data-filename=\"{0}\">删除</button></td>
                    </tr>",
                    file_path,
                    name,
                    size,
                    modified
                )
            }
        })
        .collect::<String>();

    let current_path = if path.is_empty() {
        "/".to_string()
    } else {
        path.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    };

    let html = format!(
        "<!DOCTYPE html>
        <html>
            <head>
                <meta charset=\"UTF-8\">
                <title>文件管理</title>
                <style>
                    .container {{
                        max-width: 800px;
                        margin: 0 auto;
                        padding: 20px;
                        box-sizing: border-box;
                    }}
                    #upload-section {{
                        margin-bottom: 30px;
                    }}
                    #search-container {{
                        margin-bottom: 20px;
                    }}
                    #search-input {{
                        width: 100%;
                        padding: 8px;
                        box-sizing: border-box;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                    }}
                    #progress-container {{
                        width: 100%;
                        background-color: #f3f3f3;
                        border: 1px solid #ccc;
                        margin-top: 10px;
                        height: 25px;
                        border-radius: 5px;
                        overflow: hidden;
                    }}
                    #progress-bar {{
                        width: 0%;
                        height: 100%;
                        background-color: #4caf50;
                        text-align: center;
                        color: white;
                        line-height: 25px;
                        transition: width 0.2s;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                    }}
                    th, td {{
                        padding: 10px;
                        text-align: left;
                        border: 1px solid #ddd;
                    }}
                    th {{
                        background-color: #f2f2f2;
                    }}
                    #status {{
                        margin-top: 10px;
                        color: red;
                    }}
                    .delete-button {{
                        padding: 5px 10px;
                        background-color: #f44336;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }}
                    .delete-button:hover {{
                        background-color: #d32f2f;
                    }}
                </style>
            </head>
            <body>
                <div class=\"container\">
                    <div id=\"upload-section\">
                        <h1>文件上传 - 当前路径: {1}</h1>
                        <form id=\"upload-form\" enctype=\"multipart/form-data\" action=\"/?path={1}\" method=\"post\">
                            <input type=\"file\" name=\"file\" required>
                            <button type=\"submit\">上传</button>
                        </form>
                        <div id=\"progress-container\">
                            <div id=\"progress-bar\"></div>
                        </div>
                        <div id=\"status\"></div>
                    </div>
                    <div id=\"search-container\">
                        <input type=\"text\" id=\"search-input\" placeholder=\"搜索文件...\" />
                    </div>
                    <h1>文件列表 - 当前路径: {1}</h1>
                    <table id=\"file-table\">
                        <tr>
                            <th>文件名</th>
                            <th>大小</th>
                            <th>修改时间</th>
                            <th>目录</th>
                            <th>操作</th>
                        </tr>
                        {0}
                    </table>
                </div>
                <script>
                    const form = document.getElementById('upload-form');
                    const progressBar = document.getElementById('progress-bar');
                    const status = document.getElementById('status');
                    const searchInput = document.getElementById('search-input');
                    const fileTable = document.getElementById('file-table');

                    form.addEventListener('submit', function(event) {{
                        event.preventDefault();
                        const formData = new FormData(form);
                        const xhr = new XMLHttpRequest();

                        xhr.open('POST', '/?path={1}');

                        xhr.upload.addEventListener('progress', function(e) {{
                            if (e.lengthComputable) {{
                                const percent = (e.loaded / e.total) * 100;
                                progressBar.style.width = percent + '%';
                                progressBar.textContent = Math.round(percent) + '%';
                            }}
                        }});

                        xhr.onload = function() {{
                            if (xhr.status === 200) {{
                                window.location.reload();
                            }} else {{
                                status.textContent = '上传失败: ' + xhr.statusText;
                            }}
                        }};

                        xhr.onerror = function() {{
                            status.textContent = '上传失败';
                        }};

                        xhr.send(formData);
                    }});

                    searchInput.addEventListener('keyup', function() {{
                        const filter = searchInput.value.toLowerCase();
                        const rows = fileTable.getElementsByTagName('tr');

                        for (let i = 1; i < rows.length; i++) {{
                            const cells = rows[i].getElementsByTagName('td');
                            const fileName = cells[0].textContent.toLowerCase();
                            if (fileName.includes(filter)) {{
                                rows[i].style.display = '';
                            }} else {{
                                rows[i].style.display = 'none';
                            }}
                        }}
                    }});

                    // 删除文件功能
                    const deleteButtons = document.querySelectorAll('.delete-button');
                    deleteButtons.forEach(button => {{
                        button.addEventListener('click', function() {{
                            const filename = this.getAttribute('data-filename');
                            if (confirm(`确定要删除文件 \"${{decodeURIComponent(filename)}}\" 吗？`)) {{
                                const xhr = new XMLHttpRequest();
                                xhr.open('DELETE', `/delete/${{encodeURIComponent(filename)}}`);
                                xhr.onload = function() {{
                                    if (xhr.status === 200) {{
                                        window.location.reload();
                                    }} else {{
                                        alert('删除失败: ' + xhr.statusText);
                                    }}
                                }};
                                xhr.onerror = function() {{
                                    alert('删除失败');
                                }};
                                xhr.send();
                            }}
                        }});
                    }});
                </script>
            </body>
        </html>",
        file_rows,
        current_path
    );

    Ok(Html(html))
}
// 上传文件处理
async fn upload_file(Path(path): Path<String>, Extension(state): Extension<Arc<AppState>>, mut multipart: Multipart) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let safe_path = match state.get_safe_path(&path) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        error!("无法解析上传的文件字段: {:?}", e);
        (StatusCode::BAD_REQUEST, "无法解析上传的文件字段")
    })? {
        let file_name = field.file_name().ok_or_else(|| {
            error!("未提供文件名");
            (StatusCode::BAD_REQUEST, "未提供文件名")
        })?.to_string();

        // 验证文件名，防止路径遍历攻击
        if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
            error!("无效的文件名: {}", file_name);
            return Err((StatusCode::BAD_REQUEST, "无效的文件名"));
        }

        let data = field.bytes().await.map_err(|e| {
            error!("无法读取文件数据: {:?}", e);
            (StatusCode::BAD_REQUEST, "无法读取文件数据")
        })?;

        let file_path = safe_path.join(&file_name);
        let canonical = file_path.canonicalize().map_err(|e| {
            error!("无法解析文件路径 {:?}: {:?}", file_path, e);
            (StatusCode::BAD_REQUEST, "无效的文件路径")
        })?;

        if !canonical.starts_with(&state.root_dir) {
            error!("尝试上传文件到无效路径: {:?}", canonical);
            return Err((StatusCode::FORBIDDEN, "无法上传到指定路径"));
        }

        fs::write(&canonical, &data).await.map_err(|e| {
            error!("无法保存文件 {:?}: {:?}", canonical, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "无法保存文件")
        })?;

        info!("成功上传文件: {:?}", canonical);
    }

    Ok(Json(UploadResponse {
        status: "success".to_string(),
    }))
}

// 删除文件处理函数
async fn delete_file(Path(filename): Path<String>, Extension(state): Extension<Arc<AppState>>) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    // 验证文件名，防止路径遍历攻击
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        error!("无效的文件名尝试删除: {}", filename);
        return Err((StatusCode::BAD_REQUEST, "无效的文件名"));
    }

    let file_path = match state.get_safe_path(&filename) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };

    if file_path.is_dir() {
        return Err((StatusCode::BAD_REQUEST, "无法删除目录"));
    }

    if !file_path.exists() {
        error!("尝试删除不存在的文件: {}", filename);
        return Err((StatusCode::NOT_FOUND, "文件不存在"));
    }

    fs::remove_file(&file_path).await.map_err(|e| {
        error!("无法删除文件 {}: {:?}", filename, e);
        (StatusCode::INTERNAL_SERVER_ERROR, "无法删除文件")
    })?;

    info!("成功删除文件: {}", filename);
    Ok(StatusCode::OK)
}

// 下载文件处理
async fn download_file(Path(path): Path<String>, Extension(state): Extension<Arc<AppState>>) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let safe_path = match state.get_safe_path(&path) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };

    if safe_path.is_dir() {
        return Err((StatusCode::BAD_REQUEST, "无法下载目录"));
    }

    if !safe_path.exists() {
        error!("文件不存在: {:?}", safe_path);
        return Err((StatusCode::NOT_FOUND, "文件不存在"));
    }

    let data = fs::read(&safe_path).await.map_err(|e| {
        error!("无法读取文件 {:?}: {:?}", safe_path, e);
        (StatusCode::INTERNAL_SERVER_ERROR, "无法读取文件")
    })?;

    let file_name = safe_path.file_name().and_then(|n| n.to_str()).unwrap_or("文件");

    let disposition = format!("attachment; filename=\"{}\"", file_name);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_DISPOSITION, disposition)
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(boxed(Full::from(data)))
        .unwrap())
}

// 辅助函数：拼接路径
fn path_join(current: &str, name: &str) -> String {
    if current == "/" {
        format!("{}/", name)
    } else {
        format!("{}/{}", current.trim_end_matches('/'), name)
    }
}

// 格式化文件大小
fn format_size(size: u64) -> String {
    let kb = 1024u64;
    let mb = kb * 1024;
    let gb = mb * 1024;

    if size >= gb {
        format!("{:.2} GB", size as f64 / gb as f64)
    } else if size >= mb {
        format!("{:.2} MB", size as f64 / mb as f64)
    } else if size >= kb {
        format!("{:.2} KB", size as f64 / kb as f64)
    } else {
        format!("{} B", size)
    }
}