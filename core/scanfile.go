package core

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ScanFile() {
	var filename string
	i := 0
	// 读取关键字文件，里面可以是危险函数如system()等
	keywordsFile, err := os.Open("keywords.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer keywordsFile.Close()

	// 将读取到的关键字以切片的形式储存
	keywordsScanner := bufio.NewScanner(keywordsFile)
	var keywords []string
	for keywordsScanner.Scan() {
		keyword := keywordsScanner.Text()
		keywords = append(keywords, keyword)
	}

	// 读取目标文件内容
	fmt.Println("Please input the target file:")
	fmt.Scanln(&filename)
	targetFile, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer targetFile.Close()

	// 匹配关键字，输出匹配的关键字，被匹配到的行号以及内容，直到匹配到最后一个关键字
	targetScanner := bufio.NewScanner(targetFile)
	for targetScanner.Scan() {
		line := targetScanner.Text()
		i++
		for _, keyword := range keywords {
			if strings.Contains(line, keyword) {
				fmt.Println("Keyword found:", keyword)
				fmt.Printf("Line: %d %s\n", i, line)
			}
			if keyword == "username" {
				break
			}
		}
	}

	if err := targetScanner.Err(); err != nil {
		fmt.Println(err)
		return
	}
}
