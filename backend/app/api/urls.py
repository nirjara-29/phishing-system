from fastapi import APIRouter
router = APIRouter()

@router.get("/test-url")
def test():
    return {"msg": "url working"}