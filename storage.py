"""
Storage abstraction layer for TSN Mempool.
Supports both Redis (default) and Firestore (when credentials provided).
"""

import os
from abc import ABC, abstractmethod
from typing import Any, Optional

# Check for Firebase credentials
FIREBASE_CREDS = os.environ.get("FIREBASE_PRIVATE_KEY")
USE_FIRESTORE = bool(FIREBASE_CREDS)


class StorageBackend(ABC):
    """Abstract storage interface."""
    
    @abstractmethod
    async def init(self) -> None:
        """Initialize connection."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close connection."""
        pass
    
    @abstractmethod
    async def set_intent(self, key: str, data: dict) -> None:
        """Store intent."""
        pass
    
    @abstractmethod
    async def get_intent(self, key: str) -> Optional[dict]:
        """Get intent."""
        pass
    
    @abstractmethod
    async def list_intents(self, limit: int = 50) -> list:
        """List intents."""
        pass
    
    @abstractmethod
    async def delete_intent(self, key: str) -> None:
        """Delete intent."""
        pass
    
    @abstractmethod
    async def set_claim(self, key: str, data: dict) -> None:
        """Store claim request."""
        pass
    
    @abstractmethod
    async def get_claim(self, key: str) -> Optional[dict]:
        """Get claim."""
        pass
    
    @abstractmethod
    async def list_claims(self, intent_keys: list, limit: int = 100) -> list:
        """List claims by intent keys."""
        pass
    
    @abstractmethod
    async def delete_claim(self, key: str) -> None:
        """Delete claim."""
        pass


# Redis implementation (default)
if not USE_FIRESTORE:
    import redis.asyncio as aioredis
    
    class RedisStorage(StorageBackend):
        def __init__(self, url: str = "redis://localhost:6379"):
            self.url = url
            self._redis = None
            self.ns = "tsn"
        
        async def init(self) -> None:
            self._redis = await aioredis.from_url(self.url, decode_responses=True)
        
        async def close(self) -> None:
            if self._redis:
                await self._redis.aclose()
        
        def _k(self, table: str, key: str) -> str:
            return f"{self.ns}:{table}:{key}"
        
        async def set_intent(self, key: str, data: dict) -> None:
            await self._redis.hset(self._k("intents", key), mapping=data)
        
        async def get_intent(self, key: str) -> Optional[dict]:
            data = await self._redis.hgetall(self._k("intents", key))
            return data or None
        
        async def list_intents(self, limit: int = 50) -> list:
            keys = await self._redis.keys(f"{self.ns}:intents:*")
            keys = keys[:limit]
            pipe = self._redis.pipeline()
            for k in keys:
                pipe.hgetall(k)
            results = await pipe.execute()
            return [dict(r) for r in results if r]
        
        async def delete_intent(self, key: str) -> None:
            await self._redis.delete(self._k("intents", key))
        
        async def set_claim(self, key: str, data: dict) -> None:
            await self._redis.hset(self._k("claims", key), mapping=data)
        
        async def get_claim(self, key: str) -> Optional[dict]:
            data = await self._redis.hgetall(self._k("claims", key))
            return data or None
        
        async def list_claims(self, intent_keys: list, limit: int = 100) -> list:
            pipe = self._redis.pipeline()
            for ik in intent_keys[:limit]:
                pipe.hgetall(self._k("claims", ik))
            results = await pipe.execute()
            return [dict(r) for r in results if r]
        
        async def delete_claim(self, key: str) -> None:
            await self._redis.delete(self._k("claims", key))


# Firestore implementation (needs credentials)
else:
    try:
        from google.cloud import firestore_async
        
        class FirestoreStorage(StorageBackend):
            def __init__(self, project_id: str):
                self.project_id = project_id
                self._db = None
            
            async def init(self) -> None:
                self._db = firestore_async.AsyncClient(project=self.project_id)
            
            async def close(self) -> None:
                pass  # Firestore manages connection
            
            async def set_intent(self, key: str, data: dict) -> None:
                await self._db.collection("intents").document(key).set(data)
            
            async def get_intent(self, key: str) -> Optional[dict]:
                doc = await self._db.collection("intents").document(key).get()
                return doc.to_dict() if doc.exists else None
            
            async def list_intents(self, limit: int = 50) -> list:
                docs = self._db.collection("intents").limit(limit).stream()
                return [doc.to_dict() async for doc in docs]
            
            async def delete_intent(self, key: str) -> None:
                await self._db.collection("intents").document(key).delete()
            
            async def set_claim(self, key: str, data: dict) -> None:
                await self._db.collection("claims").document(key).set(data)
            
            async def get_claim(self, key: str) -> Optional[dict]:
                doc = await self._db.collection("claims").document(key).get()
                return doc.to_dict() if doc.exists else None
            
            async def list_claims(self, intent_keys: list, limit: int = 100) -> list:
                results = []
                for ik in intent_keys[:limit]:
                    docs = self._db.collection("claims").where("intent_id", "==", ik).stream()
                    async for doc in docs:
                        results.append(doc.to_dict())
                return results
            
            async def delete_claim(self, key: str) -> None:
                await self._db.collection("claims").document(key).delete()
    except ImportError:
        # Fallback if firebase not installed
        FirestoreStorage = None


# Factory function
def get_storage():
    """Get storage backend based on environment."""
    if USE_FIRESTORE:
        if FirestoreStorage is None:
            raise RuntimeError("Firebase not installed: pip install google-cloud-firestore")
        project_id = os.environ.get("FIREBASE_PROJECT_ID", "tsn-mempool")
        return FirestoreStorage(project_id)
    else:
        return RedisStorage(os.environ.get("REDIS_URL", "redis://localhost:6379"))