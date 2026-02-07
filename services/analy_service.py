from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from cores.posrgrass import Files, Uploads

async def get_file_by_hash(
    session: AsyncSession,
    file_hash: str
) -> Files | None:
    result = await session.execute(
        select(Files).where(Files.file_hash == file_hash)
    )
    return result.scalar_one_or_none()

async def delete_table_files(
    session: AsyncSession,
    file_hash: str
) -> bool:
    result = await session.execute(
        delete(Files).where(Files.file_hash == file_hash)
    )
    await session.commit()
    return result.rowcount > 0

async def insert_table_files(
    session: AsyncSession,
    *,
    file_hash: str,
    file_path: str,
    file_type: str,
    file_size: int
) -> Files:
    file = Files(
        file_hash=file_hash,
        file_path=file_path,
        file_type=file_type,
        file_size=file_size
    )
    session.add(file)
    await session.commit()
    await session.refresh(file)
    return file

async def insert_table_uploads(
    session: AsyncSession,
    *,
    uid: int,
    fid: int,
    task_id: str | None = None,
    privacy: bool = True
) -> Uploads:
    upload = Uploads(
        uid=uid,
        fid=fid,
        task_id=task_id,
        privacy=privacy
    )

    session.add(upload)
    await session.commit()
    await session.refresh(upload)

    return upload