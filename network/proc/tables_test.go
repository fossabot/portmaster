// +build linux

package proc

import (
	"fmt"
	"testing"
)

func TestSockets(t *testing.T) {
	connections, listeners, err := GetTCP4Table()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("\nTCP 4 connections:")
	for _, connection := range connections {
		pid := FindPID(connection.UID, connection.Inode)
		fmt.Printf("%d: %+v\n", pid, connection)
	}
	fmt.Println("\nTCP 4 listeners:")
	for _, listener := range listeners {
		pid := FindPID(listener.UID, listener.Inode)
		fmt.Printf("%d: %+v\n", pid, listener)
	}

	connections, listeners, err = GetTCP6Table()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("\nTCP 6 connections:")
	for _, connection := range connections {
		pid := FindPID(connection.UID, connection.Inode)
		fmt.Printf("%d: %+v\n", pid, connection)
	}
	fmt.Println("\nTCP 6 listeners:")
	for _, listener := range listeners {
		pid := FindPID(listener.UID, listener.Inode)
		fmt.Printf("%d: %+v\n", pid, listener)
	}

	binds, err := GetUDP4Table()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("\nUDP 4 binds:")
	for _, bind := range binds {
		pid := FindPID(bind.UID, bind.Inode)
		fmt.Printf("%d: %+v\n", pid, bind)
	}

	binds, err = GetUDP6Table()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("\nUDP 6 binds:")
	for _, bind := range binds {
		pid := FindPID(bind.UID, bind.Inode)
		fmt.Printf("%d: %+v\n", pid, bind)
	}
}
