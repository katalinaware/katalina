package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/beevik/etree"
)

// ParsePlist returns a map of the elements in the dict of a valid plist xml file.
func ParsePlist(path string) (map[string]interface{}, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromFile(path)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("error: could not create a tree from file %s", path)
	}
	root := doc.SelectElement("plist")
	if root == nil {
		return nil, errors.New("error: xml tree does not have a plist element")
	}
	child := root.SelectElement("dict")
	if child == nil {
		return nil, fmt.Errorf("error: plist xml tree does not have a dict child")
	}
	childElements, err := parsePlistTree(child)
	if err != nil {
		return nil, fmt.Errorf("error: could no parse the dict tree from the plist: %v", err)
	}
	return childElements, err
}

func parsePlistTree(node *etree.Element) (map[string]interface{}, error) {
	var key string
	fItems := make(map[string]interface{})

	if node == nil {
		return nil, fmt.Errorf("error: node is nil")
	}
	for _, item := range node.ChildElements() {
		if item.Tag == "key" {
			key = item.Text()
		} else {
			if key == "" {
				return nil, errors.New("format error:" + item.Tag)
			}
			value, err := parseXMLValue(item)
			if err != nil {
				return nil, err
			}
			fItems[key] = value
			key = ""
		}
	}
	return fItems, nil
}

func parseXMLValue(item *etree.Element) (interface{}, error) {
	switch item.Tag {
	case "string":
		return item.Text(), nil
	case "array":
		return parsePlistArray(item)
	case "date":
		return time.Parse(time.RFC3339, item.Text())
	case "false":
		return false, nil
	case "true":
		return true, nil
	case "data":
		return base64.StdEncoding.DecodeString(item.Text())
	case "dict":
		return parsePlistTree(item)
	case "integer":
		value, err := strconv.Atoi(item.Text())
		if err == nil {
			return value, nil
		}
		return strconv.ParseInt(item.Text(), 10, 64)
	case "real":
		value, err := strconv.ParseFloat(item.Text(), 64)
		if err != nil {
			return nil, err
		}
		return value, nil
	case "key":
		return item.Text(), nil
	default:
		return nil, errors.New("Undefined type:" + item.Tag)
	}
}

func parsePlistArray(node *etree.Element) (interface{}, error) {
	nodes := node.ChildElements()

	if stringArray, ok := parseStringArray(nodes); ok {
		return stringArray, nil
	}
	if dataArray, ok := parseDataArray(nodes); ok {
		return dataArray, nil
	}

	var values []interface{}
	for _, item := range nodes {
		value, err := parseXMLValue(item)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func parseStringArray(nodes []*etree.Element) ([]string, bool) {
	for _, item := range nodes {
		if item.Tag != "string" {
			return nil, false
		}
	}
	values := make([]string, len(nodes))
	for i, item := range nodes {
		values[i] = item.Text()
	}
	return values, true
}

func parseDataArray(nodes []*etree.Element) ([][]byte, bool) {
	for _, item := range nodes {
		if item.Tag != "data" {
			return nil, false
		}
	}
	values := make([][]byte, len(nodes))
	for i, item := range nodes {
		v, _ := base64.StdEncoding.DecodeString(item.Text())
		values[i] = v
	}
	return values, true
}
