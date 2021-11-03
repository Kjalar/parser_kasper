import requests
from bs4 import BeautifulSoup
import sys
import sqlite3
import time
import multiprocessing
from pprint import pprint


HEADERS = {'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0',
           'accept': '*/*'}
count_page = 2
product_name = ' '.join(sys.argv[1:]).strip().lower()
if product_name == '':
    print('Введите именование продукта.\nПример использования программы:\n>>>python parser_kasper.py Google Chrome')
    sys.exit()


def get_html(page_no):
    data = {
        'action': "infinite_scroll",
        'page_no': f"{page_no}",
        'post_type': "vulnerability",
        'template': "row_vulnerability4archive",
        's': f"{product_name}",
        'q': f"{product_name}",
    }
    response = requests.post('https://threats.kaspersky.com/en/wp-admin/admin-ajax.php', headers=HEADERS, data=data)
    return response


def get_cve(link):
    cve_dict = {}
    response = requests.get(link, headers=HEADERS)
    soup = BeautifulSoup(response.text, 'html.parser')
    cve_card_html = soup.find('div', class_='cve-ids-list')
    if cve_card_html:
        cve_names = cve_card_html.find_all('a', class_='gtm_vulnerabilities_cve')
        for cve_name in cve_names:
            cve_dict[cve_name.text] = cve_name.get('href')
    return cve_dict


def get_content(html):
    data = []
    soup = BeautifulSoup(html.text, 'html.parser')
    items = soup.find_all('tr', class_='line_info line_info_vendor line_list2')

    for item in items:
        product = item.find('a', class_='gtm_vulnerabilities_vendor').get_text(strip=True)
        if product.lower() == product_name:
            lab_id = item.find('a', class_='gtm_vulnerabilities_lab_id')
            link = lab_id.get('href')
            cve_dict = get_cve(link)
            data.append({
                'Product': product,
                'Kaspersky ID': lab_id.get_text(strip=True),
                'CVE': cve_dict,
                'Name': item.find('a', class_='gtm_vulnerabilities_name').get_text(strip=True),
            })
    return data


def check_bd():
    con = sqlite3.connect('parser_data.db')
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS parser_db(
    kasp_id TEXT NOT NULL PRIMARY KEY, 
    name TEXT NOT NULL, 
    products TEXT NOT NULL, 
    cve TEXT);
    """)
    con.commit()
    return con, cur


def write_to_bd(data):
    con, cur = check_bd()
    query = "INSERT OR IGNORE INTO parser_db VALUES (?, ?, ?, ?)"
    for i in data:
        cve_string = ''
        for cve, link in i['CVE'].items():
            cve_string += f'{cve} {link}\n'
        if cve_string == '':
            cve_string = None

        cur.execute(query, (i['Kaspersky ID'], i['Name'], i['Product'], cve_string))
    con.commit()


def merge_content(content):
    result = []
    for i in content:
        result += i
    return result


def parse():
    html_list = []
    count = 1
    print('Ищем информацию. Пожалуйста, подождите...')

    t1 = time.monotonic()
    while True:
        html = get_html(count)
        if html.text.strip() == '':
            break
        count += 1
        html_list.append(html)
    if not html_list:
        print('Поиск не дал результатов.')
        sys.exit()
    t2 = time.monotonic()
    print(t2 - t1)

    print('Разбираем полученную информацию...')
    pool = multiprocessing.Pool(multiprocessing.cpu_count())
    content = pool.map(get_content, html_list)
    content = merge_content(content)
    if not content:
        print('Продукт с данным наименованием не выявлен.')
        sys.exit()
    pool.close()
    t3 = time.monotonic()
    print(t3 - t1)

    print('Записываем данные в базу данных... ')
    write_to_bd(content)
    print('Готово.')


if __name__ == '__main__':
    parse()
