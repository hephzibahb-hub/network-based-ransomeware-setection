from fastapi import FastAPI, UploadFile, File
from inference.predict import predict_connlog
import tempfile
import shutil

app = FastAPI(title="NeuroDefender AI", version="1.0")

@app.get("/")
def root():
    return {"message": "NeuroDefender API is running"}

@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    # Store uploaded file to temp path
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        temp_path = tmp.name

    # Run prediction
    results = predict_connlog(temp_path)

    # Format output
    formatted = [
        {"row": i+1, "label": lbl, "confidence": float(conf)}
        for i, (lbl, conf) in enumerate(results)
    ]

    # Summary
    summary = {}
    for lbl, _ in results:
        summary[lbl] = summary.get(lbl, 0) + 1

    return {
        "total_rows": len(results),
        "summary": summary,
        "predictions": formatted[:40],  # limit output
        "note": "Only first 40 rows shown."
    }
