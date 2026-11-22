# Firestore Security Specification (Phase 0 TDD)

## 1. Data Invariants

1. **Identity Isolation**: A user may only read, create, or update documents inside `/users/{userId}/settings/{settingId}` and `/users/{userId}/notes/{noteId}` where `userId == request.auth.uid`, `request.auth.token.email_verified == true`, and `data.ownerId == request.auth.uid`.
2. **Strict Schema Enforcement**: Every write must contain exact allowed keys (`hasAll` + `hasOnly` on create; `affectedKeys().hasOnly(...)` on update) matching `firebase-blueprint.json` with strict string `.size()` bounds (`webAppUrl <= 2048`, `sheetName` 1..120, `label <= 120`, `content` 1..20000).
3. **Path Variable Hardening**: Every single-document operation (`get`, `create`, `update`, `delete`) enforces `isValidId()` (`^[a-zA-Z0-9_\-]+$`, `<= 128` chars) on `{userId}`, `{settingId}`, and `{noteId}`.
4. **Immutability & Temporal Integrity**: `ownerId` and `createdAt` are immutable after creation; `createdAt == request.time` on create; `updatedAt == request.time` on create and update.
5. **Permanent Preservation (No Deletion)**: Both `settings` and `notes` forbid client deletion (`allow delete: if false;`) to guarantee saved URLs, tab names, and notepad entries remain permanently stored.
6. **Secure List Queries**: `allow list` on `/users/{userId}/notes/{noteId}` enforces `isVerifiedOwner(userId) && resource.data.ownerId == request.auth.uid`.

## 2. The "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)

1. **Unauthenticated Read**: `GET /users/uidA/settings/googleSync` with `auth == null`.
2. **Unverified Email Write**: `CREATE /users/uidA/settings/googleSync` with `auth.uid == 'uidA'` and `email_verified == false`.
3. **Cross-Tenant Read**: `GET /users/uidA/notes/note1` by authenticated verified `uidB`.
4. **Identity Spoofing on Create**: `CREATE /users/uidA/notes/note1` by `uidA` with `ownerId: 'uidB'`.
5. **Shadow / Ghost Field Injection**: `CREATE /users/uidA/settings/googleSync` with extra key `isAdmin: true`.
6. **ID Poisoning**: `CREATE /users/uidA/notes/bad..id/../../x` or 200-char ID string.
7. **Denial-of-Wallet Oversized URL**: `UPDATE /users/uidA/settings/googleSync` with `webAppUrl` length 5000 (`> 2048`).
8. **Oversized Note Content**: `CREATE /users/uidA/notes/note2` with `content` length 25000 (`> 20000`).
9. **Empty Note Content**: `CREATE /users/uidA/notes/note3` with `content: ""`.
10. **Immutable Field Tampering**: `UPDATE /users/uidA/settings/googleSync` modifying `createdAt` or `ownerId`.
11. **Client-Forged Timestamp**: `CREATE /users/uidA/notes/note4` passing a past timestamp instead of `request.time` (`serverTimestamp()`).
12. **Unauthorized Deletion**: `DELETE /users/uidA/notes/note1` or `DELETE /users/uidA/settings/googleSync` even by owner `uidA`.
