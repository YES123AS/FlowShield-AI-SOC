from datetime import datetime
from extensions import db
class Admin(db.Model):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(100))
    last_login_time = db.Column(db.DateTime)
class LogModel(db.Model):
    __tablename__ = "log"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    op_name = db.Column(db.String(100), nullable=False)
    op_user = db.Column(db.String(100), nullable=False)
    op_time = db.Column(db.DateTime, default=datetime.now)
class UserModel(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), nullable=True, unique=True)
    join_time = db.Column(db.DateTime, default=datetime.now)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(100))
    last_login_time = db.Column(db.DateTime)

class QuestionModel(db.Model):
    __tablename__ = "question"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)

    # 外键
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = db.relationship(UserModel, backref="questions")


class AnswerModel(db.Model):
    __tablename__ = "answer"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.Text, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)

    # 外键
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    # 关系
    question = db.relationship(QuestionModel, backref=db.backref("answers", order_by=create_time.desc()))
    author = db.relationship(UserModel, backref="answers")

class TrafficModel(db.Model):
    __tablename__ = 'traffic_results'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    detection_result = db.Column(db.Text, nullable=False)  # 存储检测状态（如"流量正常"或攻击类型）
    attack_type = db.Column(db.String(100))  # 新增：明确存储攻击类型（如"DDoS"）
    protocol_distribution = db.Column(db.Text)  # 新增：存储协议分布（JSON字符串）
    attack_distribution = db.Column(db.Text)  # 新增：存储攻击分布（JSON字符串）
    malicious_ratio = db.Column(db.Float, default=0.0)  # 恶意流量占比，0-100
    risk_score = db.Column(db.Integer, default=0)  # 风险分数，0-100
    severity = db.Column(db.String(50), default="normal")  # 风险等级
    confidence = db.Column(db.Float)  # 模型置信度，0-1
    evidence_json = db.Column(db.Text)  # 证据 JSON
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)  # 确保已导入datetime


class SecurityIncidentModel(db.Model):
    __tablename__ = "security_incident"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    traffic_id = db.Column(db.Integer, db.ForeignKey("traffic_results.id"))
    traffic = db.relationship(
        "TrafficModel",
        backref=db.backref("incidents", cascade="all, delete-orphan", lazy=True)
    )

    incident_no = db.Column(db.String(100), nullable=False, unique=True)
    title = db.Column(db.String(255), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default="open")

    summary = db.Column(db.Text)
    cause_analysis = db.Column(db.Text)
    impact_analysis = db.Column(db.Text)
    attack_chain = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    evidence_json = db.Column(db.Text)

    ai_report = db.Column(db.Text)
    llm_used = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
