from config import vuln_app
import os

# Tiempo de vida del token (segundos)
alive = int(os.getenv('tokentimetolive', 60))

if __name__ == '__main__':
    vuln_app.run(host='0.0.0.0', port=5000, debug=True)
