from utils.security.response_playbook import get_recommendations


def get_playbook(attack_type):
    return get_recommendations(attack_type)
