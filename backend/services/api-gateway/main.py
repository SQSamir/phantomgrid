from fastapi import FastAPI
app = FastAPI(title='api-gateway')
@app.get('/health')
async def health(): return {'status':'ok'}
