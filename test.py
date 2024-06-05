import tldextract

def is_potential_phishing(url):
    suspicious_keywords = ['login', 'signin', 'password', 'verify', 'account', 'update', 'secure', 'bank']
   
    
    # Extraer el dominio del URL
    domain = tldextract.extract(url).domain
    
    # Calcular la longitud del dominio
    domain_length = len(domain)
    
    # Verificar si el dominio contiene palabras clave sospechosas
    contains_suspicious_keywords = any(keyword in domain.lower() for keyword in suspicious_keywords)
    
    # Verificar si el dominio coincide con estándares ISO
    matches_iso_standards = any(iso_standard.lower() in domain.lower() for iso_standard in iso_standards)
    
    # Calcular el puntaje de sospecha basado en varios factores
    suspicion_score = 0
    
    if domain_length <= 10:
        suspicion_score += 10
    
    if contains_suspicious_keywords:
        suspicion_score += 30
    
    if matches_iso_standards:
        suspicion_score -= 20
    
    # Normalizar el puntaje de sospecha al rango del 0 al 100%
    suspicion_score = max(0, min(100, suspicion_score))
    
    return suspicion_score

# Test del script
url = input("Ingrese el URL para verificar si es phishing: ")
phishing_likelihood = is_potential_phishing(url)
print(f"La probabilidad de que el URL proporcionado sea phishing es del {phishing_likelihood}%.")
