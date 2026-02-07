from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from cores.posrgrass import Files

async def get_file_by_hash(
    session: AsyncSession,
    file_hash: str
) -> Files | None:
    result = await session.execute(
        select(Files).where(Files.file_hash == file_hash)
    )
    return result.scalar_one_or_none()

async def create_file(
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

