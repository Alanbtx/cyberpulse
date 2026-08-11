from datetime import datetime, timezone

def calculate_custom_risk_score(cvss_score: str, known_exploited: bool, cisa_date_added) -> float:
    """
    Fórmula de Priorização (Fase 4):
    - CVSS Base (peso 40%) -> (cvss / 10) * 10 * 0.4
    - CISA KEV (peso 40%) -> Se True = 10 * 0.4
    - Recência (peso 20%) -> Se adicionado nos últimos 30 dias = 10 * 0.2, senão 5 * 0.2
    
    Retorna uma nota de 0 a 10.
    """
    
    # 1. Componente CVSS (0 a 4 pontos)
    cvss = 5.0 # Média se for desconhecido
    if cvss_score:
        try:
            cvss = float(cvss_score)
        except:
            pass
    score_cvss = cvss * 0.4
    
    # 2. Componente CISA (0 a 4 pontos)
    score_cisa = 4.0 if known_exploited else 0.0
    
    # 3. Componente Recência (0 a 2 pontos)
    score_recency = 1.0 # Padrão (antigo)
    if cisa_date_added:
        now = datetime.now().date()
        try:
            # cisa_date_added é do tipo datetime.date no model
            diff = (now - cisa_date_added).days
            if diff <= 30:
                score_recency = 2.0
        except:
            pass
            
    total_score = score_cvss + score_cisa + score_recency
    return round(total_score, 1)
