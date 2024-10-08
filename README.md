# bts-technical-test
Please read this README as it contains important information and notes.
You can view each commits I made to track the progress (that exceed the given time).

## Techstack
- Python
- FastAPI
- MySQL (further development)
- Prisma (further development)

## Finished Endpoint Progress
- POST login
- POST register
- POST checklist
- GET checklist
- POST checklist/{checklistId}/item
- DELETE checklist
- GET checklist/{checklistId} 

Completed but exceeding the 120 minutes given:
- GET checklist/{checklistId}/item/{itemId}
- PUT checklist/{checklistId}/item/{itemId}
- PUT checklist/{checklistId}/item/rename/{itemId}
- DLETE checklist/{checklistId}/item/{itemId}

## Todo
- Finished incompleted endpoints ✅ (completed after the 120 minutes given)
- Implement UI
- Connect to Database using ORM

## Notes
- API implemented without using database (because it's not in the requirement and the time is limited)
- Data stored in Memory (variables)
- JWT implemented without external (non-default) library
- Hash used are SHA256
- For the Delete Checklist endpoint, body are used instead of param to store the checklist id (because its not supported in FastAPI)
- UUID ared used instead of integer/number as the ID, as I believe it is the more suitable practice.
- I didn't use the same parameter/variabel name format (snake_case instead of camelCase as instructed) as the snake_case fit Python better that the camelCase.

Sorry for not completing the project/test on time.
I tried to make several changes even after the given time limit because I have to finish what I start (at least the bare minimum of the requirements). But I believe you can just check the previous commits to see my progress for the given time.

Don't forget to check my other projects/repositories.

Thank you