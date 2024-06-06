import os

class Config:
    SUSPICIOUS_KEYWORDS = os.getenv('SUSPICIOUS_KEYWORDS', 'login,signin,password,verify,account,update,secure,bank').split(',')
    ISO_STANDARDS = os.getenv('ISO_STANDARDS', 'com,org,net,edu').split(',')
