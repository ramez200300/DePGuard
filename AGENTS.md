# AGENTS.md
> Rules for any AI coding agent working in this repo.
> Read this before writing any code.

## Read first
- PRD.md, SRS.md, MVP_SCOPE.md. Build only what is IN scope.

## Stack
- Language: Python 3.9+ (standard library preferred)
- CLI: Typer
- Web Framework: Flask
- Database: SQLite3 (using `sqlite3` stdlib, NO ORMs)
- HTTP: requests
- PDF: fpdf2

## Commands
- Install: `pip install -r requirements.txt`
- Run CLI: `python src/cli.py <command>`
- Run Web: `python src/app.py`
- Test: Manual testing (execute the command and verify the output).

## Never
- Edit or print .env or any secret.
- Add async/await or threads.
- Add ORM (SQLAlchemy, Peewee, etc.).
- Add complex design patterns (Repositories, Services, Dependency Injection).
- Add a dependency without asking.
- Build features marked OUT or LATER in MVP_SCOPE.md (e.g., Docker, Auth).
- Create a function longer than 30 lines.
- Create a file longer than 200 lines.

## Always
- Write simple, readable code suitable for a Cybersecurity Bachelor's student.
- Small commits, one feature each (follow the FR-XX IDs in SRS.md).
- Ask before any change that is not in SRS.md.
- Keep functions pure where possible (input -> output).
- Use standard library modules whenever possible.