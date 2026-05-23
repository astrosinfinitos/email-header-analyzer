import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from parser import parse_header
from reputation import check_all_ips
from report import generate_report

app = FastAPI(title="Email Header Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

class HeaderRequest(BaseModel):
    raw_header: str

class ReportRequest(BaseModel):
    analysis: dict

@app.post("/analyze")
async def analyze(req: HeaderRequest):
    data = parse_header(req.raw_header)
    ips = [hop["ip"] for hop in data.get("hops", []) if hop.get("ip")]
    data["reputation"] = await check_all_ips(ips)
    return data

@app.post("/report")
def report(req: ReportRequest):
    return generate_report(req.analysis)