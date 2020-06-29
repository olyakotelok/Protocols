usage: Сканер портов. Проверка открытых udp и tcp портов. Вводим либо все параметры, либо ни одного. (надо доработать парсинг аргументов)
       [-h] [-host HOST] [-mb MIN_BOUNDARY] [-maxb MAX_BOUNDARY]
       [-tcp TCP_SCAN] [-udp UDP_SCAN] [-other OTHER_SCAN]
       [-thr THREADS_COUNT]

optional arguments:
  -h, --help            show this help message and exit
  -host HOST, --host HOST
                        хост
  -mb MIN_BOUNDARY, --min_boundary MIN_BOUNDARY
                        нижняя граница поиска
  -maxb MAX_BOUNDARY, --max_boundary MAX_BOUNDARY
                        верхняя граница поиска
  -tcp TCP_SCAN, --tcp_scan TCP_SCAN
                        сканируем tcp? yes/no
  -udp UDP_SCAN, --udp_scan UDP_SCAN
                        сканируем udp? yes/no
  -other OTHER_SCAN, --other_scan OTHER_SCAN
                        сканируем остальное? yes/no
  -thr THREADS_COUNT, --threads_count THREADS_COUNT
                        число потоков. по дефолту не меньше 25
