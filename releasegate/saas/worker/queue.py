from redis import Redis
from rq import Queue
from compliancebot.saas.config import SaaSConfig

# Redis Connection
redis_conn = Redis.from_url(SaaSConfig.REDIS_URL)

# Job Queue
# "default" is the standard queue name
job_queue = Queue("default", connection=redis_conn)
