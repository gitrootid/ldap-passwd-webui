package app

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
)

func getTitle() string {
	return GetEnvStr("LPW_TITLE", "Change your password on example.org")
}

//func getPattern() string {
//	return GetEnvStr("LPW_PATTERN", ".{10,}")
//}

func getPatternInfo() string {
	return GetEnvStr("LPW_PATTERN_INFO",
		"密码须包含(大写，小写，数字，特殊字符)中的3种字符.Password must contains 3 kinds of symbol among capital, lowercase letter, number, special symbol.")
}

func GetEnvStr(key, defaultValue string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}
	return defaultValue
}

func GetEnvInt(key string, defaultValue int) int {
	val := os.Getenv(key)
	if val != "" {
		i, err := strconv.Atoi(val)
		if err != nil {
			return defaultValue
		}
		return i
	}
	return defaultValue
}

func GetEnvBool(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val != "" {
		b, err := strconv.ParseBool(val)
		if err != nil {
			return defaultValue
		}
		return b
	}
	return defaultValue
}

func CheckPasswordStrength(pw string, min int, max int) (level int, msg string) {
	if len(pw) < min {
		msg = fmt.Sprintf("password len < %d\n", min)
		return
	}
	if len(pw) > max {
		msg = fmt.Sprintf("password len > %d\n", max)
		return
	}
	var regStringList = []string{`[0-9]{1}`,
		`[a-z]{1}`,
		`[A-Z]{1}`,
		`\W{1}`,
	}
	for _, regStr := range regStringList {
		b, err := regexp.MatchString(regStr, pw)
		if err != nil {
			log.Print(err.Error())
			continue
		}
		if b {
			level += 1
		}
	}
	msg = getPatternInfo()
	return
}
