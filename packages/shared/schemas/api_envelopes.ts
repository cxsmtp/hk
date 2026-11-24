export type ListEnvelope<T> = {
  items: T[];
  total: number;
  page: number;
  page_size: number;
};
