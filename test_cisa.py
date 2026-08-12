import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, Date
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    title = Column(String, index=True)
    description = Column(Text, nullable=True)
    vendor = Column(String, nullable=True)
    product = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(String, nullable=True)
    known_exploited = Column(Boolean, default=False)
    cisa_date_added = Column(Date, nullable=True)
    cisa_required_action = Column(Text, nullable=True)
    cisa_due_date = Column(Date, nullable=True)

engine = create_engine("sqlite:///./test.db")
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def test_fetch():
    import httpx
    db = SessionLocal()
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = httpx.get(url)
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])
    
    novas = 0
    for item in vulnerabilities:
        cve_id = item.get("cveID")
        date_added_str = item.get("dateAdded")
        due_date_str = item.get("dueDate")
        date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date() if date_added_str else None
        due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None
        
        db_vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
        if not db_vuln:
            nova_vuln = Vulnerability(
                cve_id=cve_id,
                title=item.get("vulnerabilityName"),
                cisa_date_added=date_added,
                cisa_due_date=due_date
            )
            db.add(nova_vuln)
            novas += 1
    db.commit()
    print(f"Added {novas} vulns.")
    
    # query recent
    recent = db.query(Vulnerability).order_by(Vulnerability.cisa_date_added.desc()).limit(1).first()
    print(f"Most recent: {recent.cve_id} on {recent.cisa_date_added}")

if __name__ == "__main__":
    test_fetch()
