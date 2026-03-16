import pickle
import yaml

# SEC001 — hardcoded secret
api_key = "xK9mP2vL8nQ5wR3yT7zA4bC1dE6fG0hJ"
db_password = "hX7#kP2$mL9@nQ5wR"

# SEC004 — insecure deserialization
def load_session(data):
    return pickle.loads(data)

def load_config(path):
    with open(path) as f:
        return yaml.load(f)