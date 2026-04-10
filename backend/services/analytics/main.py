from fastapi import FastAPI
app = FastAPI(title='analytics')
@app.get('/health')
async def health(): return {'status':'ok'}
@app.get('/overview')
async def overview():
    return {'active_decoys':0,'events_today':0,'alerts':0,'attackers':0}
