import os
from urllib.parse import quote_plus

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

try:
    from dotenv import load_dotenv
    load_dotenv(ENV_PATH)
except ImportError:
    pass

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
if not SECRET_KEY:
    raise RuntimeError("未配置 SECRET_KEY。请复制 .env.example 为 .env，并生成随机密钥。")

# 数据库的配置信息
DB_ENGINE = os.getenv("DB_ENGINE", "mysql" if os.path.exists(ENV_PATH) else "sqlite").lower()
DATABASE_URL = os.getenv("DATABASE_URL", "")
HOSTNAME = os.getenv("DB_HOST", "127.0.0.1")
PORT = os.getenv("DB_PORT", "3306")
DATABASE = os.getenv("DB_NAME", "traffic_system")
USERNAME = os.getenv("DB_USER", "root")
PASSWORD = os.getenv("DB_PASSWORD", "")

if DATABASE_URL:
    DB_URI = DATABASE_URL
elif DB_ENGINE == "sqlite":
    sqlite_name = os.getenv("DB_NAME", "traffic_system.db")
    if sqlite_name == ":memory:":
        DB_URI = "sqlite:///:memory:"
    else:
        sqlite_path = sqlite_name if os.path.isabs(sqlite_name) else os.path.join(BASE_DIR, sqlite_name)
        DB_URI = "sqlite:///" + sqlite_path.replace("\\", "/")
elif DB_ENGINE == "mysql":
    DB_URI = 'mysql+pymysql://{}:{}@{}:{}/{}?charset=utf8'.format(
        quote_plus(USERNAME),
        quote_plus(PASSWORD),
        HOSTNAME,
        PORT,
        DATABASE
    )
else:
    raise RuntimeError(f"Unsupported DB_ENGINE: {DB_ENGINE}")

SQLALCHEMY_DATABASE_URI = DB_URI
SQLALCHEMY_TRACK_MODIFICATIONS = False
AUTO_CREATE_TABLES = os.getenv("AUTO_CREATE_TABLES", "true" if DB_ENGINE == "sqlite" else "false").lower() == "true"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

CAPTURE_FOLDER = "captured_traffic"
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(20 * 1024 * 1024)))
RESIDUAL_MLP_MODEL_PATH = os.getenv(
    "RESIDUAL_MLP_MODEL_PATH",
    os.path.join(BASE_DIR, "models", "residual_mlp_best.pt")
)
RESIDUAL_MLP_SCALER_PATH = os.getenv(
    "RESIDUAL_MLP_SCALER_PATH",
    os.path.join(BASE_DIR, "models", "scaler.joblib")
)
DETECTOR_BACKEND = os.getenv("DETECTOR_BACKEND", "transformer")
TRANSFORMER_MODEL_PATH = os.getenv(
    "TRANSFORMER_MODEL_PATH",
    os.path.join(BASE_DIR, "models", "transformer_best.pt")
)
TRANSFORMER_SCALER_PATH = os.getenv(
    "TRANSFORMER_SCALER_PATH",
    os.path.join(BASE_DIR, "models", "scaler.joblib")
)
TRANSFORMER_BATCH_SIZE = int(os.getenv("TRANSFORMER_BATCH_SIZE", "512"))
TRANSFORMER_MALICIOUS_FLOW_THRESHOLD = float(
    os.getenv("TRANSFORMER_MALICIOUS_FLOW_THRESHOLD", "0.30")
)
TRANSFORMER_DRIFT_Z_THRESHOLD = float(os.getenv("TRANSFORMER_DRIFT_Z_THRESHOLD", "8.0"))

# DeepSeek AI-SOC 配置。默认关闭，开启后使用 OpenAI 兼容接口生成安全事件报告。
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")
DEEPSEEK_ENABLE = os.getenv("DEEPSEEK_ENABLE", "false").lower() == "true"

# 运行步骤
# 1 配置环境
# 2 删除migrations文件夹
# 3 新建数据库，名为traffic_system
# 4 命令行依次输入flask db init   flask db migrate  flask db upgrade   即可自动创建数据库表
# 5 python app.py
# 注意：Transformer 推理必须使用训练阶段对应的 transformer_best.pt 和 scaler.joblib
