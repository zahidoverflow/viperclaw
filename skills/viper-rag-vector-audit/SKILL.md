---
name: viper-rag-vector-audit
description: RAG Pipeline, Embedding & Vector Database Security Auditor. Reviews Pinecone/Qdrant/Milvus/pgvector tenant ACL filtering, indirect document poisoning, and chunk sanitization.
---

# ViperClaw Skill 36: RAG Pipeline & Vector Database Security Auditor (`viper-rag-vector-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** OWASP LLM01 (Indirect Prompt Injection), OWASP LLM06 (Sensitive Information Disclosure), OWASP LLM08 (Vector and Embedding Weaknesses).
- **Focus:** Auditing Retrieval-Augmented Generation (RAG) ingestion pipelines, vector store queries (`pgvector`, Pinecone, Qdrant, Weaviate, Milvus, Chroma), and context assembly.

## 2. Rapid Discovery Patterns
- Search for vector queries: `.similarity_search(`, `.query(vector=`, ` <=> `, ` <-> `, ` VectorStoreIndex`, `RetrievalQA`.
- Check whether `filter=` / `where=` metadata predicates include the authenticated caller's `tenant_id` and `user_id`.

## 3. Technical Audit Checklist
1. **Mandatory Pre-Query Tenant & ACL Filtering:** Vector similarity searches must enforce mandatory metadata filters (`filter={"tenant_id": current_user.tenant_id, "acl_groups": {"$in": user.groups}}`) *inside* the vector index query—never rely on LLM prompt instructions to ignore unauthorized chunks.
2. **Document Ingestion Sanitization:** Strip hidden HTML/CSS (`display:none`, `font-size:0`, white-on-white text), invisible Unicode tag characters (`U+E0000`–`U+E007F`), and PDF annotation layers during document chunking.
3. **Untrusted Context Delimiting:** Wrap retrieved RAG chunks in explicit XML/JSON data tags (`<retrieved_document source_id="...">...</retrieved_document>`) and instruct the system prompt to treat contents strictly as passive reference data.
4. **Citation & Grounding Verification:** Validate that any URLs or markdown images emitted in the LLM's response match domains present in the authorized retrieved documents (preventing markdown image data exfiltration).
5. **Permission Sync on Document Revocation:** Ensure deleting or revoking access to a source document immediately deletes or updates its corresponding vector embeddings.

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: Global similarity search across all tenants
docs = vector_store.similarity_search(user_query, k=5)

# ✅ HARDENED: Pre-filtered vector search scoped to verified tenant & role
docs = vector_store.similarity_search(
    user_query,
    k=5,
    filter={"tenant_id": session.verified_tenant_id, "visibility": {"$in": session.allowed_scopes}},
)
```
