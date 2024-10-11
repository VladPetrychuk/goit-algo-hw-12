import psycopg2

try:
    connection = psycopg2.connect(
        user="myuser",
        password="mypassword",
        host="localhost",
        port="5433",
        database="mydatabase"
    )
    cursor = connection.cursor()
    cursor.execute("SELECT version();")
    record = cursor.fetchone()
    print("You are connected to - ", record)
except Exception as e:
    print("Error while connecting to PostgreSQL", e)
finally:
    if connection:
        cursor.close()
        connection.close()
        print("PostgreSQL connection is closed")