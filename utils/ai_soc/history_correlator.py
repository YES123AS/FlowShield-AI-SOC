from datetime import timedelta

from models import SecurityIncidentModel


def correlate_history(traffic_record, attack_type):
    upload_time = getattr(traffic_record, "upload_time", None)
    query = SecurityIncidentModel.query.filter(
        SecurityIncidentModel.attack_type == attack_type,
        SecurityIncidentModel.traffic_id != traffic_record.id
    )

    if upload_time:
        query = query.filter(
            SecurityIncidentModel.created_at >= upload_time - timedelta(days=7),
            SecurityIncidentModel.created_at <= upload_time + timedelta(days=7)
        )

    similar_count = query.count()
    if similar_count:
        return {
            "similar_count": similar_count,
            "description": f"近 7 天内发现 {similar_count} 条同类型安全事件，建议关注是否存在持续性攻击行为。"
        }
    return {
        "similar_count": 0,
        "description": "近 7 天内未发现同类型历史安全事件。"
    }
