# Security Specification: Task Manager ABAC

## 1. Data Invariants
1. **Task Boundary Integrity**: A task cannot exist without a creator ID that matches the creating user's authenticated UID.
2. **Assignee Validation**: A task can only be assigned to either the creator themselves or another user who exists in the `/users` table.
3. **Immortal Fields**: Once a task is created, its `id`, `creatorId`, and `createdAt` are fully immutable.
4. **Tiered Authorization**: 
   - Only the Creator of a task can modify details (title, description, priority, assignee, due date).
   - The Assignee of a task can *only* transition the `status` and `updatedAt` of that task.

## 2. The "Dirty Dozen" Threat Payloads (Verification Cases)
The following payloads and requests must return `PERMISSION_DENIED`:

| Case | Collection | Action | Payload / Scenario | Expected Gate Trigger |
|---|---|---|---|---|
| 1 | `users` | create | User attempts to Register profile with a different user's UID as document ID. | identity check: `request.auth.uid == userId` |
| 2 | `users` | update | User attempts to modify their registration `/users/{myId}` to inject a ghost field `role: 'admin'`. | schema check & `affectedKeys().hasOnly()` |
| 3 | `users` | create | Unverified user (`email_verified == false`) attempts to register profile. | verification check: `request.auth.token.email_verified == true` |
| 4 | `tasks` | create | User attempts to create a task with missing `creatorId`. | structure check: `isValidTask(data)` |
| 5 | `tasks` | create | User attempts to create a task with `creatorId: 'spy'` (spoofing creator) while authenticated as `user1`. | integrity check: `incoming().creatorId == request.auth.uid` |
| 6 | `tasks` | create | User attempts to create a task assigned to a non-existent assignee userId `non_existent_id`. | global consistency: `exists(/databases/.../users/assigneeId)` |
| 7 | `tasks` | create | User attempts to create a task with an exceptionally large title to exhaust storage. | length limit: `data.title.size() <= 256` |
| 8 | `tasks` | update | Assignee attempts to sneakily change the task `title` in addition to transitioning `status`. | tiered identity bounds: assignee only affectedKeys hasOnly `status` & `updatedAt` |
| 9 | `tasks` | update | A user who is neither the creator nor the assignee attempts to transition a task status. | access gate: only creator or assignee allowed to write |
| 10 | `tasks` | update | Creator attempts to change the immutable `creatorId` during update. | immortal field: `incoming().creatorId == existing().creatorId` |
| 11 | `tasks` | delete | Assignee (not creator) attempts to delete the task. | creator gate: `isCreator(existing())` |
| 12 | `tasks` | list | Authenticated user attempts to list all tasks in Firestore without filtering by creatorId or assigneeId. | query enforcer restriction on list resources |

## 3. Test Runner Design
We secure these constraints strictly using pure, mathematically air-tight Firestore Security Rules matching the `firebase-blueprint.json` schema. All operations will be caught by the standard catch-all deny-all gate unless explicitly allowed.
