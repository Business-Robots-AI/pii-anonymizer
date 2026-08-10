"""
Database of Uzbek and Russian names for PII detection.
Includes common misspellings and transliteration variants.
"""

# Узбекские мужские имена (кириллица + латиница + варианты)
UZBEK_MALE_NAMES = {
    # А
    "Абдулла", "Абдуллах", "Абдулло", "Abdulla", "Abdullah",
    "Абдумалик", "Абдуманноб", "Абдурахим", "Абдурахмон", "Abdurakhmon",
    "Абдусамад", "Абдухалил", "Абдулазиз", "Abdulaziz",
    "Аброр", "Abror", "Адхам", "Adham", "Азамат", "Azamat",
    "Азиз", "Aziz", "Азизбек", "Azizbek", "Акбар", "Akbar",
    "Акмал", "Akmal", "Акрам", "Akram", "Али", "Ali",
    "Алишер", "Alisher", "Алихан", "Alikhan",
    "Анвар", "Anvar", "Анор", "Anor", "Аслан", "Aslan",
    "Асрор", "Asror", "Атабек", "Atabek",
    # Б
    "Бахром", "Bakhrom", "Бахтиёр", "Bakhtiyor", "Бахтияр",
    "Бек", "Bek", "Бекзод", "Bekzod", "Бехруз", "Bekhruz",
    "Билол", "Bilol", "Бобур", "Bobur", "Ботир", "Botir",
    "Буняд", "Bunyod",
    # В
    "Вали", "Vali", "Валижон", "Valijon",
    # Г
    "Голиб", "Golib",
    # Д
    "Давлат", "Davlat", "Давронбек", "Davronbek",
    "Далер", "Daler", "Диёр", "Diyor", "Дилмурод", "Dilmurod",
    "Дилшод", "Dilshod", "Достон", "Doston",
    # Ё
    "Ёдгор", "Yodgor", "Ёкуб", "Yokub",
    # Ж
    "Жавлон", "Javlon", "Жамол", "Jamol", "Жамшид", "Jamshid",
    "Жасур", "Jasur", "Жахонгир", "Jahongir",
    # З
    "Завкиддин", "Zavkiddin", "Зафар", "Zafar", "Зиёд", "Ziyod",
    "Зокир", "Zokir", "Зухриддин", "Zuhriddin",
    # И
    "Ибрагим", "Ibrohim", "Ibrahim", "Икром", "Ikrom",
    "Илхом", "Ilhom", "Илхомжон", "Ilhomjon", "Ислом", "Islom", "Islam",
    "Исмоил", "Ismoil", "Ismail",
    # К
    "Камол", "Kamol", "Камолиддин", "Kamoliddin", "Камрон", "Kamron",
    "Карим", "Karim", "Комил", "Komil", "Кудрат", "Qudrat",
    # Л
    "Лазиз", "Laziz", "Лочин", "Lochin",
    # М
    "Мадияр", "Madiyar", "Максуд", "Maqsud", "Малик", "Malik",
    "Мансур", "Mansur", "Мардон", "Mardon", "Махмуд", "Mahmud",
    "Мирзо", "Mirzo", "Миршод", "Mirshod", "Мирзоҳид", "Mirzohid",
    "Музаффар", "Muzaffar", "Мурод", "Murod", "Мухаммад", "Muhammad", "Мухаммед",
    "Муҳаммад", "Мухтор", "Mukhtor",
    # Н
    "Навруз", "Navruz", "Нажмиддин", "Najmiddin", "Насим", "Nasim",
    "Нодир", "Nodir", "Нодирбек", "Nodirbek", "Нуриддин", "Nuriddin",
    "Нурислом", "Nurislom", "Нурмухаммад", "Nurmuhammad",
    # О
    "Обид", "Obid", "Одил", "Odil", "Озод", "Ozod",
    "Олим", "Olim", "Омон", "Omon", "Орзу", "Orzu",
    "Ориф", "Orif", "Отабек", "Otabek",
    # П
    "Пулат", "Pulat",
    # Р
    "Равшан", "Ravshan", "Рамазон", "Ramazon", "Расул", "Rasul",
    "Рахим", "Rakhim", "Рахмон", "Rakhmon", "Рустам", "Rustam",
    # С
    "Саид", "Said", "Сайфиддин", "Sayfiddin", "Салим", "Salim",
    "Самир", "Samir", "Сардор", "Sardor", "Сирож", "Siroj",
    "Собир", "Sobir", "Сухроб", "Suhrob",
    # Т
    "Тимур", "Timur", "Темур", "Temur", "Толиб", "Tolib", "Тохир", "Tohir",
    "Турсун", "Tursun", "Туйчи", "Tuychi",
    # У
    "Улугбек", "Ulugbek", "Умар", "Umar", "Умид", "Umid",
    "Умиджон", "Umidjon", "Урал", "Ural", "Уткир", "Utkir",
    # Ф
    "Фарход", "Farhod", "Фаррух", "Farrukh", "Фахриддин", "Fakhriddin",
    "Фирдавс", "Firdavs", "Фозил", "Fozil",
    # Х
    "Хайрулла", "Khayrulla", "Хакимжон", "Khakimjon", "Хамза", "Khamza",
    "Хасан", "Khasan", "Хикмат", "Khikmat", "Хуршид", "Khurshid",
    "Хусан", "Khusan", "Хусниддин", "Khusniddin",
    # Ш
    "Шавкат", "Shavkat", "Шамсиддин", "Shamsiddin", "Шерзод", "Sherzod",
    "Шоҳрух", "Shohrukh", "Шохрух", "Шукур", "Shukur", "Шухрат", "Shukhrat",
    # Э
    "Элбек", "Elbek", "Элдор", "Eldor", "Элёр", "Elyor", "Эркин", "Erkin",
    "Эшмат", "Eshmat", "Эргаш", "Ergash", "Эсон", "Eson",
    # Ю
    "Юнус", "Yunus", "Юсуф", "Yusuf",
    # Я
    "Яхё", "Yahyo", "Яшнар", "Yashnar",
}

# Узбекские женские имена
UZBEK_FEMALE_NAMES = {
    # А
    "Адиба", "Adiba", "Азиза", "Aziza", "Айгуль", "Aygul",
    "Айша", "Aysha", "Анора", "Anora", "Асила", "Asila",
    # Б
    "Барно", "Barno", "Бибигул", "Bibigul", "Бунафша", "Bunafsha",
    # Г
    "Гавхар", "Gavkhar", "Гулнора", "Gulnora", "Гулноза", "Gulnoza",
    "Гулчехра", "Gulchekhra", "Гузал", "Guzal",
    # Д
    "Дилафруз", "Dilafruz", "Дилбар", "Dilbar", "Дилдора", "Dildora",
    "Дилноза", "Dilnoza", "Динора", "Dinora", "Дурдона", "Durdona",
    # З
    "Замира", "Zamira", "Зарина", "Zarina", "Зебо", "Zebo",
    "Зилола", "Zilola", "Зулфия", "Зульфия", "Zulfiya", "Зухра", "Zukhra",
    # И
    "Ирода", "Iroda",
    # К
    "Камила", "Kamila", "Комила", "Komila",
    # Л
    "Лайло", "Laylo", "Лола", "Lola",
    # М
    "Мадина", "Madina", "Малика", "Malika", "Манзура", "Manzura",
    "Мафтуна", "Maftuna", "Мохира", "Mokhira", "Мунира", "Munira",
    # Н
    "Наргиза", "Nargiza", "Нафиса", "Nafisa", "Нигора", "Nigora",
    "Нигина", "Nigina", "Нилуфар", "Nilufar", "Нодира", "Nodira", "Нозима", "Nozima",
    # О
    "Озода", "Ozoda",
    # Р
    "Рано", "Rano", "Рухшона", "Rukhshona",
    # С
    "Садокат", "Sadoqat", "Саида", "Saida", "Салима", "Salima",
    "Сарвиноз", "Sarvinoz", "Севара", "Sevara", "Ситора", "Sitora",
    # Ф
    "Фарида", "Farida", "Фариза", "Fariza", "Фазилат", "Fazilat",
    "Феруза", "Feruza", "Фотима", "Fotima",
    # Х
    "Хадича", "Khadicha", "Хилола", "Khilola", "Хурсанд", "Khursand",
    # Ш
    "Шахло", "Shahlo", "Шахноза", "Shakhnoza", "Шоира", "Shoira",
    # Ю
    "Юлдуз", "Yulduz",
}

# Русские мужские имена (включая уменьшительные формы)
RUSSIAN_MALE_NAMES = {
    # А
    "Александр", "Саша", "Сашка", "Шура", "Алексей", "Лёша", "Алёша", "Лёха",
    "Анатолий", "Толя", "Толик", "Андрей", "Андрюша", "Андрюха",
    "Антон", "Тоша", "Аркадий", "Аркаша", "Артём", "Артем", "Тёма",
    "Артур",
    # Б
    "Богдан", "Борис", "Боря",
    # В
    "Вадим", "Вадик", "Валентин", "Валя", "Валерий", "Валера",
    "Василий", "Вася", "Виктор", "Витя", "Витёк",
    "Виталий", "Виталик", "Владимир", "Вова", "Володя",
    "Владислав", "Влад", "Всеволод", "Сева", "Вячеслав", "Слава",
    # Г
    "Геннадий", "Гена", "Георгий", "Жора", "Гоша", "Глеб",
    "Григорий", "Гриша",
    # Д
    "Даниил", "Данил", "Данила", "Даня", "Денис",
    "Дмитрий", "Дима", "Димон", "Митя",
    # Е
    "Евгений", "Женя", "Егор", "Егорка",
    # И
    "Иван", "Ваня", "Ванька", "Игорь", "Илья", "Илюша",
    # К
    "Кирилл", "Кира", "Константин", "Костя", "Костик",
    # Л
    "Леонид", "Лёня", "Лев",
    # М
    "Максим", "Макс", "Михаил", "Миша", "Мишка",
    # Н
    "Никита", "Николай", "Коля", "Колян",
    # О
    "Олег",
    # П
    "Павел", "Паша", "Пашка", "Пётр", "Петр", "Петя",
    # Р
    "Роман", "Рома", "Ромка", "Руслан",
    # С
    "Семён", "Семен", "Сеня", "Сергей", "Серёжа", "Серёга", "Серый",
    "Станислав", "Стас", "Степан", "Стёпа",
    # Т
    "Тимофей", "Тима", "Тимур",
    # Ф
    "Фёдор", "Федор", "Федя",
    # Э
    "Эдуард", "Эдик",
    # Ю
    "Юрий", "Юра", "Юрка",
    # Я
    "Ярослав", "Ярик",
}

# Русские женские имена
RUSSIAN_FEMALE_NAMES = {
    # А
    "Александра", "Саша", "Сашенька", "Алёна", "Алена", "Алина",
    "Алиса", "Алла", "Анастасия", "Настя", "Настенька",
    "Анна", "Аня", "Анюта", "Антонина", "Тоня",
    # В
    "Валентина", "Валя", "Валерия", "Лера", "Варвара", "Варя",
    "Вера", "Вероника", "Ника", "Виктория", "Вика",
    # Г
    "Галина", "Галя",
    # Д
    "Дарья", "Даша", "Дашенька", "Диана", "Дина",
    # Е
    "Ева", "Евгения", "Женя", "Екатерина", "Катя", "Катюша",
    "Елена", "Лена", "Леночка", "Елизавета", "Лиза",
    # З
    "Зинаида", "Зина", "Зоя",
    # И
    "Инна", "Ирина", "Ира", "Ирочка",
    # К
    "Карина", "Кристина", "Ксения", "Ксюша",
    # Л
    "Лариса", "Лара", "Лидия", "Лида", "Лилия", "Лиля",
    "Людмила", "Люда", "Люся", "Любовь", "Люба",
    # М
    "Маргарита", "Рита", "Марина", "Мария", "Маша", "Машенька",
    # Н
    "Надежда", "Надя", "Наталья", "Наталия", "Наташа",
    "Нина",
    # О
    "Оксана", "Ольга", "Оля", "Оленька",
    # П
    "Полина", "Поля",
    # Р
    "Раиса", "Рая", "Регина",
    # С
    "Светлана", "Света", "София", "Софья", "Соня",
    # Т
    "Тамара", "Тома", "Татьяна", "Таня",
    # Ю
    "Юлия", "Юля",
    # Я
    "Яна",
}

# Узбекские фамилии (с окончаниями и без)
UZBEK_SURNAMES = {
    "Абдуллаев", "Абдуллаева", "Abdullayev", "Abdullayeva",
    "Азимов", "Азимова", "Azimov", "Azimova",
    "Алимов", "Алимова", "Alimov", "Alimova",
    "Ахмедов", "Ахмедова", "Akhmedov", "Akhmedova",
    "Исаков", "Исакова", "Isakov", "Isakova",
    "Исмаилов", "Исмаилова", "Ismailov", "Ismailova",
    "Каримов", "Каримова", "Karimov", "Karimova",
    "Маматов", "Маматова", "Mamatov", "Mamatova",
    "Мирзаев", "Мирзаева", "Mirzayev", "Mirzayeva",
    "Мухамедов", "Мухамедова", "Mukhamedov", "Mukhamedova",
    "Насыров", "Насырова", "Nasirov", "Nasirova",
    "Норов", "Норова", "Norov", "Norova",
    "Рахимов", "Рахимова", "Rakhimov", "Rakhimova",
    "Раупов", "Раупова", "Raupov", "Raupova",
    "Салимов", "Салимова", "Salimov", "Salimova",
    "Сулейманов", "Сулейманова", "Suleymanov", "Suleymanova",
    "Ташматов", "Ташматова", "Tashmatov", "Tashmatova",
    "Турсунов", "Турсунова", "Tursunov", "Tursunova",
    "Умаров", "Умарова", "Umarov", "Umarova",
    "Усманов", "Усманова", "Usmanov", "Usmanova",
    "Хакимов", "Хакимова", "Khakimov", "Khakimova",
    "Холматов", "Холматова", "Kholmatov", "Kholmatova",
    "Шарипов", "Шарипова", "Sharipov", "Sharipova",
    "Эргашев", "Эргашева", "Ergashev", "Ergasheva",
    "Юлдашев", "Юлдашева", "Yuldashev", "Yuldasheva",
    "Юсупов", "Юсупова", "Yusupov", "Yusupova",
    # ── Expansion 2026-06-07: transliterated Central Asian + Persian +
    # Tajik surnames flagged by customer report (Farkhadi leak). These
    # are surnames that don't fit the -ов/-ев/-ский suffix heuristics so
    # the regex pass missed them; backed by explicit dictionary entries.
    "Фархади", "Farkhadi", "Farhadi", "Фарходи",
    "Назари", "Nazari", "Назаров", "Назарова",
    "Хайдари", "Хайдарова", "Khaydari", "Khaydarov",
    "Бахтиёри", "Bakhtiyori", "Бахтияров",
    "Махмудов", "Махмудова", "Makhmudov", "Makhmudova",
    "Ниязов", "Ниязова", "Niyazov", "Niyazova",
    "Хамидов", "Хамидова", "Khamidov", "Khamidova",
    "Назарбаев", "Назарбаева", "Nazarbayev", "Nazarbayeva",
    "Ахмадов", "Ахмадова", "Akhmadov", "Akhmadova",
    "Бабаев", "Бабаева", "Babayev", "Babayeva",
    "Бекмурадов", "Бекмурадова", "Bekmuradov", "Bekmuradova",
    "Достиев", "Достиева", "Dostiyev", "Dostiyeva",
    "Жуманазаров", "Жуманазарова", "Jumanazarov", "Jumanazarova",
    "Зайнидинов", "Зайнидинова", "Zaynidinov", "Zaynidinova",
    "Иргашев", "Иргашева", "Irgashev", "Irgasheva",
    "Касымов", "Касымова", "Kasymov", "Kasymova", "Kasimov",
    "Кодиров", "Кодирова", "Kodirov", "Kodirova", "Qodirov",
    "Курбонов", "Курбонова", "Qurbonov", "Qurbonova",
    "Мадаминов", "Мадаминова", "Madaminov", "Madaminova",
    "Назиров", "Назирова", "Nazirov", "Nazirova",
    "Очилов", "Очилова", "Ochilov", "Ochilova",
    "Раджабов", "Раджабова", "Rajabov", "Rajabova",
    "Рашидов", "Рашидова", "Rashidov", "Rashidova",
    "Саидов", "Саидова", "Saidov", "Saidova",
    "Сафаров", "Сафарова", "Safarov", "Safarova",
    "Султанов", "Султанова", "Sultanov", "Sultanova",
    "Тошматов", "Тошматова", "Toshmatov", "Toshmatova",
    "Файзиев", "Файзиева", "Fayziyev", "Fayziyeva",
    "Файзуллаев", "Файзуллаева", "Fayzullayev", "Fayzullayeva",
    "Халилов", "Халилова", "Khalilov", "Khalilova",
    "Хасанов", "Хасанова", "Hasanov", "Hasanova", "Khasanov",
    "Холикулов", "Холикулова", "Kholiqulov", "Kholiqulova",
    "Хужаев", "Хужаева", "Khujayev", "Khujayeva",
    "Чориев", "Чориева", "Choriyev", "Choriyeva",
    "Шомуродов", "Шомуродова", "Shomurodov", "Shomurodova",
    "Юнусов", "Юнусова", "Yunusov", "Yunusova",
    "Ядгаров", "Ядгарова", "Yadgarov", "Yadgarova",
    # Kazakh / Kyrgyz
    "Жумабаев", "Жумабаева", "Jumabayev", "Jumabayeva",
    "Калиев", "Калиева", "Kaliyev", "Kaliyeva",
    "Касенов", "Касенова", "Kasenov", "Kasenova",
    "Сарсенбаев", "Сарсенбаева", "Sarsenbayev",
    "Бекболотов", "Bekbolotov",
    # Turkmen
    "Бердимухамедов", "Berdimuhamedov", "Berdimuhamedova",
    "Атаев", "Атаева", "Atayev", "Atayeva",
}

# Русские фамилии
RUSSIAN_SURNAMES = {
    "Иванов", "Иванова", "Петров", "Петрова",
    "Сидоров", "Сидорова", "Смирнов", "Смирнова",
    "Кузнецов", "Кузнецова", "Попов", "Попова",
    "Васильев", "Васильева", "Соколов", "Соколова",
    "Михайлов", "Михайлова", "Новиков", "Новикова",
    "Фёдоров", "Федоров", "Фёдорова", "Федорова",
    "Морозов", "Морозова", "Волков", "Волкова",
    "Алексеев", "Алексеева", "Лебедев", "Лебедева",
    "Козлов", "Козлова", "Степанов", "Степанова",
    "Николаев", "Николаева", "Орлов", "Орлова",
    "Андреев", "Андреева", "Макаров", "Макарова",
    "Никитин", "Никитина", "Захаров", "Захарова",
}

# Контекстные слова перед именами (на русском и узбекском)
NAME_CONTEXT_PATTERNS = [
    # Русский
    r"(?:меня зовут|зовут меня|мое имя|моё имя|я)\s+",
    r"(?:клиент|клиентка|гражданин|гражданка|господин|госпожа|товарищ)\s+",
    r"(?:уважаемый|уважаемая|дорогой|дорогая|здравствуйте)\s*,?\s*",
    r"(?:от имени|для|кому|кто)\s+",
    # Узбекский
    r"(?:mening ismim|ismim|men)\s+",
    r"(?:hurmatli|aziz|qadrli)\s+",
    r"(?:mijoz|fuqaro|janob|xonim)\s+",
]

# Среднеазиатские имена (казахские, киргизские, таджикские, туркменские, редкие узбекские)
CENTRAL_ASIAN_NAMES = {
    # Казахские мужские
    "Айбек", "Aybek", "Айдар", "Aydar", "Айдос", "Aydos", "Айнур", "Aynur",
    "Алмас", "Almas", "Алтынбек", "Altynbek", "Амангельды", "Amangeldy",
    "Амар", "Amar", "Арман", "Arman", "Арсен", "Arsen", "Арыстан", "Arystan",
    "Асан", "Asan", "Аскар", "Askar", "Асылбек", "Asylbek",
    "Бакытжан", "Bakutzhan", "Бауржан", "Baurzhan", "Бауыржан", "Bauyrzhan",
    "Бейбит", "Beybit", "Бекболат", "Bekbolat", "Бекжан", "Bekzhan",
    "Берик", "Berik", "Болат", "Bolat", "Булат", "Bulat",
    "Галым", "Galym", "Галымжан", "Galymzhan",
    "Данияр", "Daniyar", "Дастан", "Dastan", "Даулет", "Daulet",
    "Дулат", "Dulat", "Думан", "Duman",
    "Ельнур", "Elnur", "Ерасыл", "Erasyl", "Ерболат", "Erbolat",
    "Ержан", "Erzhan", "Ерлан", "Erlan", "Ермек", "Ermek",
    "Жандос", "Zhandos", "Жанибек", "Zhanibek", "Жаркын", "Zharkyn",
    "Жеңіс", "Zhenis", "Женис", "Жумабек", "Zhumabek",
    "Кайрат", "Kayrat", "Кайырбек", "Kaiyrbek", "Канат", "Kanat",
    "Куандык", "Kuandyk", "Куаныш", "Kuanysh", "Куат", "Kuat",
    "Куатбек", "Kuatbek", "Кудайберген", "Kudaibergen",
    "Марат", "Marat", "Медет", "Medet", "Мейрам", "Meiram",
    "Мурат", "Murat", "Муратбек", "Muratbek",
    "Нурбек", "Nurbek", "Нурболат", "Nurbolat", "Нуржан", "Nurzhan",
    "Нурлан", "Nurlan", "Нурсултан", "Nursultan",
    "Олжас", "Olzhas", "Орынбасар", "Orynbasar",
    "Рахат", "Rakhat", "Рустем", "Rustem",
    "Сабит", "Sabit", "Сагындык", "Sagyndyk", "Сайлау", "Saylau",
    "Санжар", "Sanzhar", "Сарсен", "Sarsen", "Серик", "Serik",
    "Талгат", "Talgat", "Темирлан", "Temirlan", "Токтар", "Toktar",
    "Толеген", "Tolegen", "Турар", "Turar",
    "Шынгыс", "Shyngys", "Шерхан", "Sherkhan",
    # Казахские женские
    "Айгерим", "Aigerim", "Айжан", "Aizhan", "Айнагуль", "Ainagul",
    "Айнур", "Айсулу", "Aisulu", "Акмарал", "Akmaral", "Алия", "Aliya",
    "Алтынай", "Altynai", "Анар", "Anar", "Асель", "Asel", "Асем", "Asem",
    "Ботагоз", "Botagoz", "Гульжан", "Gulzhan", "Гульмира", "Gulmira",
    "Гульнар", "Gulnar", "Дана", "Dana", "Даная", "Динара", "Dinara",
    "Жанар", "Zhanar", "Жансая", "Zhansaya", "Жибек", "Zhibek",
    "Карлыгаш", "Karlygash", "Куралай", "Kuralay",
    "Мадина", "Madina", "Маржан", "Marzhan", "Меруерт", "Meruert",
    "Назгуль", "Nazgul", "Нургуль", "Nurgul",
    "Сауле", "Saule", "Салтанат", "Saltanat",
    "Томирис", "Tomiris", "Толганай", "Tolganai",
    # Киргизские
    "Айбар", "Aybar", "Айтмырза", "Aitmyrza", "Алмаз", "Almaz",
    "Бакыт", "Bakyt", "Бактыбек", "Baktybek", "Баяман", "Bayaman",
    "Женишбек", "Zhenishbek", "Жоомарт", "Zhoomart",
    "Кубан", "Kuban", "Кубанычбек", "Kubanychbek", "Кылычбек", "Kylychbek",
    "Максат", "Maksat", "Манас", "Manas", "Мирбек", "Mirbek",
    "Нурдин", "Nurdin", "Нуртай", "Nurtay",
    "Сыймык", "Syimyk", "Таалай", "Taalay", "Талант", "Talant",
    "Улан", "Ulan", "Урмат", "Urmat", "Чынгыз", "Chyngyz",
    # Таджикские
    "Абдували", "Abduvali", "Акбаршо", "Akbarsho", "Бахтовар", "Bakhtovar",
    "Джамшед", "Dzhamshed", "Джахонгир", "Dzhahongir",
    "Зайниддин", "Zayniddin", "Зубайдулло", "Zubaydulla",
    "Искандар", "Iskandar", "Комрон", "Komron", "Курбон", "Kurbon",
    "Лутфулло", "Lutfulla", "Манучехр", "Manuchehr",
    "Парвиз", "Parviz", "Рустами", "Rustami", "Сайфулло", "Sayfulla",
    "Фаридун", "Faridun", "Фирдавси", "Firdavsi", "Хуршед", "Khurshed",
    "Шамсиддин", "Shamsiddin", "Шариф", "Sharif", "Шухрат", "Shukhrat",
    # Туркменские
    "Аннагелди", "Annageldi", "Аннамурат", "Annamurat",
    "Батыр", "Batyr", "Бегенч", "Begench", "Бердимурат", "Berdimurat",
    "Гурбангелди", "Gurbangeldi", "Гурбанмурат", "Gurbanmurat",
    "Довлет", "Dovlet", "Дурды", "Durdy",
    "Керим", "Kerim", "Курбан", "Kurban",
    "Мердан", "Merdan", "Мурад", "Murad", "Мырат", "Myrat",
    "Нурмурат", "Nurmurat", "Оразгелди", "Orazgeldi",
    "Пирмурат", "Pirmurat", "Рахым", "Rakhym",
    "Сапар", "Sapar", "Сердар", "Serdar", "Союнч", "Soyunch",
    "Ягмур", "Yagmur", "Язмурат", "Yazmurat",
    # Редкие узбекские и арабские
    "Абдусаттор", "Abdusattor", "Абдушукур", "Abdushukur",
    "Адолат", "Adolat", "Азодбек", "Azodbek",
    "Бобомурод", "Bobomurod", "Бойбек", "Boybek",
    "Ганижон", "Ganijon", "Гофур", "Gofur", "Гулом", "Gulom",
    "Дехкон", "Dekhkon", "Дониёр", "Doniyor",
    "Зиёвуддин", "Ziyovuddin", "Зоир", "Zoir",
    "Кобил", "Kobil", "Козим", "Kozim", "Кудратилло", "Qudratilla",
    "Кутбиддин", "Kutbiddin", "Купитдин", "Kupitdin", "Қутбиддин",
    "Лутфилло", "Lutfillo", "Лочинбек", "Lochinbek",
    "Мансурбек", "Mansurbek", "Мардонбек", "Mardonbek",
    "Маъруф", "Maruf", "Мираброр", "Mirabror", "Миралишер", "Miralisher",
    "Мирзоҳид", "Mirzohid", "Муминжон", "Muminjon", "Мухторжон", "Mukhktorjon",
    "Набижон", "Nabijon", "Насриддин", "Nasriddin", "Неъмат", "Nemat",
    "Обиджон", "Obidjon", "Озодбек", "Ozodbek", "Ойбек", "Oybek",
    "Пўлат", "Pulat", "Равшанбек", "Ravshanbek", "Рузибой", "Ruziboy",
    "Сайфуллох", "Sayfulloh", "Санжарбек", "Sanjarbek", "Сирожиддин", "Sirojiddin",
    "Собиржон", "Sobirjon", "Содиқжон", "Sodiqjon", "Султонбек", "Sultonbek",
    "Тожибой", "Tojiboy", "Толибжон", "Tolibjon", "Турдимурод", "Turdimurod",
    "Ўктам", "Oktam", "Ўткир", "Utkir", "Улмасжон", "Ulmasjon",
    "Файзулло", "Fayzullo", "Фирдавсбек", "Firdavsbek", "Фозилжон", "Foziljon",
    "Хайдар", "Khaydar", "Хамид", "Khamid", "Хамидулло", "Khamidulla",
    "Хикматулло", "Khikmatulla", "Хожиакбар", "Khojiakbar", "Хуснидин", "Khusniddin",
    "Шавкатжон", "Shavkatjon", "Шамсулло", "Shamsulla", "Шодиёр", "Shodiyor",
    "Эргаш", "Ergash", "Элчин", "Elchin", "Эшмурод", "Eshmurod",
    "Юлдошбек", "Yuldoshbek", "Юнусжон", "Yunusjon",
}

# Собираем все имена в один set для быстрого поиска
ALL_FIRST_NAMES = (
    UZBEK_MALE_NAMES | UZBEK_FEMALE_NAMES |
    RUSSIAN_MALE_NAMES | RUSSIAN_FEMALE_NAMES |
    CENTRAL_ASIAN_NAMES
)

ALL_SURNAMES = UZBEK_SURNAMES | RUSSIAN_SURNAMES

ALL_NAMES = ALL_FIRST_NAMES | ALL_SURNAMES


def is_name(word: str) -> bool:
    """Check if a word is a known name."""
    return word in ALL_NAMES or word.capitalize() in ALL_NAMES


def is_first_name(word: str) -> bool:
    """Check if a word is a known first name."""
    return word in ALL_FIRST_NAMES or word.capitalize() in ALL_FIRST_NAMES


def is_surname(word: str) -> bool:
    """Check if a word is a known surname."""
    return word in ALL_SURNAMES or word.capitalize() in ALL_SURNAMES


# Суффиксы узбекских/среднеазиатских имён для детекции составных имён
# Эти суффиксы позволяют находить редкие составные имена как Саидвалидхон, Хондамир и т.д.
UZBEK_NAME_SUFFIXES = {
    # Кириллица
    "хон", "хона",           # Саидвалидхон, Гулихон
    "мир", "амир",           # Хондамир, Шерамир
    "бек", "бег",            # Улугбек, Темирбек
    "жон", "джон",           # Алижон, Мухаммаджон
    "улло", "улла", "уллох", # Абдулло, Файзулла
    "иддин", "уддин", "оддин", "еддин",  # Нуриддин, Шамсуддин
    "бой", "бай",            # Турсунбой, Рузибай
    "гул", "гуль",           # Назгуль, Айгуль
    "нур",                   # Айнур, Гульнур
    "шох", "шоҳ", "шах",     # Шохрух, Бахтишах
    "хожа", "ходжа", "хўжа", # Мирхожа
    "мурод", "мурад",        # Дилмурод, Бахтимурад
    "жан", "джан", "зан",    # Нуржан, Айжан
    "берди", "бердi",        # Кудайберди
    "гелди", "келди",        # Оразгелди
    "бола", "болa",          # Гулбола
    "ой", "ай",              # Гулой, Ойгул
    "хан", "қан",            # Шерхан
    "солих", "солиҳ",        # Сирожсолих
    "тош", "таш",            # Олтынтош
    "пулат", "пўлат",        # Темирпулат
    "темир", "тимур",        # Нуртемир
    "болта", "болат",        # Темирболта
    "бахт", "бахти",         # Бахтиёр
    "давлат", "давлет",      # Нурдавлат
    "дост", "дуст",          # Сирдост, Юлдуст
    "назар",                 # Худойназар
    "кул", "қул",            # Абдуқул
    "али", "валид", "вали",  # Саидвалид
    "саид", "саъид",         # Саидали
}

# Латиница эквиваленты
UZBEK_NAME_SUFFIXES_LATIN = {
    "khon", "xon", "hon",
    "mir", "amir",
    "bek", "beg",
    "jon", "djon", "zhon",
    "ullo", "ulla", "ulloh",
    "iddin", "uddin", "oddin", "eddin",
    "boy", "bay",
    "gul", "guli",
    "nur",
    "shoh", "shah", "shox",
    "khoja", "hodja", "xoja",
    "murod", "murad",
    "jan", "djan", "zan", "zhan",
    "berdi",
    "geldi", "keldi",
    "bola",
    "oy", "ay",
    "khan", "xan",
    "solih",
    "tosh", "tash",
    "pulat",
    "temir", "timur",
    "bolta", "bolat",
    "bakht", "bakhti",
    "davlat", "davlet",
    "dost", "dust",
    "nazar",
    "kul", "qul",
    "ali", "valid", "vali",
    "said", "sayd",
}

# Минимальная длина слова для проверки суффикса (чтобы не ловить короткие слова)
MIN_SUFFIX_WORD_LENGTH = 6


def has_name_suffix(word: str) -> bool:
    """Check if a word has a common Uzbek name suffix."""
    if len(word) < MIN_SUFFIX_WORD_LENGTH:
        return False

    word_lower = word.lower()

    # Проверяем кириллические суффиксы
    for suffix in UZBEK_NAME_SUFFIXES:
        if word_lower.endswith(suffix):
            return True

    # Проверяем латинские суффиксы
    for suffix in UZBEK_NAME_SUFFIXES_LATIN:
        if word_lower.endswith(suffix):
            return True

    return False


def looks_like_name(word: str) -> bool:
    """
    Check if a word looks like a name based on:
    1. Is in the known names database
    2. Has a common Uzbek name suffix
    3. Starts with capital letter
    """
    if not word or len(word) < 2:
        return False

    # Должно начинаться с заглавной буквы
    if not word[0].isupper():
        return False

    # Проверяем базу имён
    if is_name(word):
        return True

    # Проверяем суффиксы
    if has_name_suffix(word):
        return True

    return False


# ============ TRANSLITERATION ============

# Uzbek Cyrillic → Latin
CYR_TO_LAT = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd',
    'е': 'e', 'ё': 'yo', 'ж': 'j', 'з': 'z', 'и': 'i',
    'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n',
    'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't',
    'у': 'u', 'ф': 'f', 'х': 'x', 'ц': 'ts', 'ч': 'ch',
    'ш': 'sh', 'ъ': '', 'ы': 'i', 'ь': '', 'э': 'e',
    'ю': 'yu', 'я': 'ya', 'ў': "o'", 'қ': 'q', 'ғ': "g'", 'ҳ': 'h',
}

# Latin → Cyrillic (digraphs first for correct parsing)
_LAT_DIGRAPHS = {'sh': 'ш', 'ch': 'ч', 'yo': 'ё', 'yu': 'ю', 'ya': 'я', 'ts': 'ц', "o'": 'ў', "g'": 'ғ'}
_LAT_SINGLE = {
    'a': 'а', 'b': 'б', 'v': 'в', 'g': 'г', 'd': 'д',
    'e': 'е', 'j': 'ж', 'z': 'з', 'i': 'и', 'y': 'й',
    'k': 'к', 'l': 'л', 'm': 'м', 'n': 'н', 'o': 'о',
    'p': 'п', 'r': 'р', 's': 'с', 't': 'т', 'u': 'у',
    'f': 'ф', 'x': 'х', 'h': 'ҳ', 'q': 'қ',
}


def transliterate_cyr_to_lat(word: str) -> str:
    """Convert Cyrillic word to Latin transliteration."""
    result = []
    for ch in word:
        low = ch.lower()
        lat = CYR_TO_LAT.get(low, ch)
        if ch.isupper() and lat:
            result.append(lat[0].upper() + lat[1:])
        else:
            result.append(lat)
    return ''.join(result)


def transliterate_lat_to_cyr(word: str) -> str:
    """Convert Latin word to Cyrillic transliteration."""
    result = []
    i = 0
    wl = word.lower()
    orig = word
    while i < len(wl):
        # Check digraphs first (2-char)
        if i + 1 < len(wl):
            digraph = wl[i:i+2]
            if digraph in _LAT_DIGRAPHS:
                cyr = _LAT_DIGRAPHS[digraph]
                if orig[i].isupper():
                    cyr = cyr.upper()
                result.append(cyr)
                i += 2
                continue
        single = _LAT_SINGLE.get(wl[i], wl[i])
        if orig[i].isupper():
            single = single.upper()
        result.append(single)
        i += 1
    return ''.join(result)


def transliterate_name(word: str) -> str:
    """Transliterate a name to the other script (Cyrillic↔Latin)."""
    if not word:
        return ''
    # Detect script by first alpha character
    for ch in word:
        if ch.isalpha():
            if '\u0400' <= ch <= '\u04ff' or '\u0500' <= ch <= '\u052f':
                return transliterate_cyr_to_lat(word)
            elif 'a' <= ch.lower() <= 'z':
                return transliterate_lat_to_cyr(word)
            break
    return word


# ============ PATRONYMIC → NAME INFERENCE ============

def extract_name_from_patronymic(patronymic: str) -> str:
    """Extract the father's base name from a patronymic.
    Алишерович → Алишер, Сергеевич → Сергей, Владимировна → Владимир
    """
    wl = patronymic.lower()
    suffix_map = [
        ('ович', ''), ('овна', ''),
        ('евич', 'й'), ('евна', 'й'),
        ('ич', ''), ('ична', ''),
    ]
    for suffix, add_back in suffix_map:
        if wl.endswith(suffix) and len(wl) > len(suffix) + 2:
            base = wl[:-len(suffix)] + add_back
            return base.capitalize()
    # Latin patronymics
    suffix_map_lat = [
        ('ovich', ''), ('ovna', ''),
        ('evich', 'y'), ('evna', 'y'),
    ]
    for suffix, add_back in suffix_map_lat:
        if wl.endswith(suffix) and len(wl) > len(suffix) + 2:
            base = wl[:-len(suffix)] + add_back
            return base.capitalize()
    return ''


# ============ FUZZY MATCHING ============

# Build name index for fast fuzzy lookup: (first_letter, length) → set of names
_NAME_FUZZY_INDEX = {}
for _n in ALL_FIRST_NAMES:
    if len(_n) >= 3:
        _key = (_n[0].lower(), len(_n))
        _NAME_FUZZY_INDEX.setdefault(_key, []).append(_n)


def _levenshtein_1(a: str, b: str) -> bool:
    """Check if Levenshtein distance between a and b is exactly 1."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for x, y in zip(a, b) if x != y) == 1
    # One is shorter by 1
    short, long_ = (a, b) if la < lb else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i+1:]


def fuzzy_match_name(word: str) -> str:
    """Find a known name within edit distance 1 of the word.
    Returns the matched name or empty string.
    """
    wl = word.lower()
    if len(wl) < 3:
        return ''
    for delta in (-1, 0, 1):
        target_len = len(wl) + delta
        key = (wl[0], target_len)
        for name in _NAME_FUZZY_INDEX.get(key, []):
            if _levenshtein_1(wl, name.lower()):
                return name
    return ''
