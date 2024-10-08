# bts-technical-test

## Techstack
- Python
- FastAPI

## Endpoint Progress
- POST login
- POST register
- POST checklist
- GET checklist
- POST checklist/{checklistId}/item
- DELETE checklist
- GET checklist/{checklistId} 

## Todo
- Finished incompleted endpoints
- Implement UI
- Connect to Database using ORM

## Notes
- API implemented without using database (because it's not in requirement and the time is limited)
- JWT implemented without external (non-default) library
- Hash used are SHA256
- For the Delete Checklist endpoint, body are used instead of param to store the checklist id (because not supported in FastAPI)