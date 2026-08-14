import { useState, useMemo } from "react";

interface UseTablePaginationOptions<T> {
  items: T[];
  pageSize?: number;
  filterFn?: (item: T, query: string) => boolean;
}

interface UseTablePaginationResult<T> {
  /** Items for the current page (after filtering). Pass this to Table `items`. */
  pageItems: T[];
  /** Total items after filtering (before pagination). */
  filteredItemsCount: number;
  /** All items after filtering (useful for selection/export). */
  filteredItems: T[];
  /** Current page index (1-based). */
  currentPage: number;
  /** Total pages. */
  totalPages: number;
  /** Page size. */
  pageSize: number;
  /** Filter query string. */
  filterQuery: string;
  /** Set the filter query. */
  setFilterQuery: (q: string) => void;
  /** Set the current page. */
  setCurrentPage: (page: number) => void;
  /** Set the page size. */
  setPageSize: (size: number) => void;
  /** Props to spread onto Cloudscape Pagination component. */
  paginationProps: {
    currentPageIndex: number;
    pagesCount: number;
    onChange: (event: { detail: { currentPageIndex: number } }) => void;
  };
}

/**
 * Hook that provides client-side filtering + pagination for Cloudscape tables.
 * All data stays in memory; only the current page is rendered.
 */
export function useTablePagination<T>({
  items,
  pageSize: initialPageSize = 25,
  filterFn,
}: UseTablePaginationOptions<T>): UseTablePaginationResult<T> {
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [filterQuery, setFilterQuery] = useState("");

  const filteredItems = useMemo(() => {
    if (!filterQuery || !filterFn) return items;
    const q = filterQuery.toLowerCase();
    return items.filter((item) => filterFn(item, q));
  }, [items, filterQuery, filterFn]);

  const totalPages = Math.max(1, Math.ceil(filteredItems.length / pageSize));

  // Reset to page 1 if filter changes make current page invalid
  const safePage = Math.min(currentPage, totalPages);

  const pageItems = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return filteredItems.slice(start, start + pageSize);
  }, [filteredItems, safePage, pageSize]);

  const handleFilterChange = (q: string) => {
    setFilterQuery(q);
    setCurrentPage(1); // Reset to first page on filter change
  };

  const handlePageSizeChange = (size: number) => {
    setPageSize(size);
    setCurrentPage(1);
  };

  return {
    pageItems,
    filteredItemsCount: filteredItems.length,
    filteredItems,
    currentPage: safePage,
    totalPages,
    pageSize,
    filterQuery,
    setFilterQuery: handleFilterChange,
    setCurrentPage,
    setPageSize: handlePageSizeChange,
    paginationProps: {
      currentPageIndex: safePage,
      pagesCount: totalPages,
      onChange: ({ detail }) => setCurrentPage(detail.currentPageIndex),
    },
  };
}
