export declare function discoverFiles(target: string): string[];
export declare function readCode(path: string): string;
export declare function toRel(root: string, abs: string): string;
/**
 * Беглая проверка, стоит ли вообще парсить файл: есть 'use server' (экшены) либо
 * привязка экшена через .bind() (секрет может уходить из клиентского компонента).
 */
export declare function mightHaveServerCode(code: string): boolean;
