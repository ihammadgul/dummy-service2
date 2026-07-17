"""Pagination utilities for Service2"""
from typing import TypeVar, Generic, List
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

T = TypeVar('T')


class PaginationResult(Generic[T]):
    """Generic pagination result"""
    def __init__(
        self,
        items: List[T],
        total_items: int,
        page: int,
        page_size: int
    ):
        self.items = items
        self.total_items = total_items
        self.page = page
        self.page_size = page_size
        self.total_pages = (total_items + page_size - 1) // page_size if total_items > 0 else 0
        self.has_next = page < self.total_pages
        self.has_previous = page > 1


async def paginate_query(
    statement,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 25
) -> PaginationResult:
    """
    Apply pagination to a SQLModel query statement
    
    Args:
        statement: SQLModel select statement
        session: Async database session
        page: Page number (1-indexed)
        page_size: Number of items per page
        
    Returns:
        PaginationResult with items and pagination metadata
    """
    # Get total count by executing the base query
    count_result = await session.exec(statement)
    total_items = len(count_result.all())
    
    # Apply pagination to the statement
    offset = (page - 1) * page_size
    paginated_statement = statement.offset(offset).limit(page_size)
    
    # Execute paginated query
    result = await session.exec(paginated_statement)
    items = result.all()
    
    return PaginationResult(
        items=items,
        total_items=total_items,
        page=page,
        page_size=page_size
    )
