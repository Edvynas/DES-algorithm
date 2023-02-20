using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DES
{
    public partial class Form1 : Form
    {
        DES des = new DES();
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string line;
            using (StreamReader inputFile = new StreamReader(textBox1.Text))
            {
                while ((line = inputFile.ReadLine()) != null)
                {
                    using (StreamWriter outputFile = new StreamWriter("C:/Users/Rugile/Desktop/Studijos/Infosaugumas/DES/DES/FileEncrypted.txt", true))
                    {
                        outputFile.WriteLine(des.Encrypt(line, textBox2.Text));
                    }
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            string line;
            using (StreamReader inputFile = new StreamReader("C:/Users/Rugile/Desktop/Studijos/Infosaugumas/DES/DES/FileEncrypted.txt"))
            {
                while ((line = inputFile.ReadLine()) != null)
                {
                    using (StreamWriter outputFile = new StreamWriter("C:/Users/Rugile/Desktop/Studijos/Infosaugumas/DES/DES/FileDecrypted.txt", true))
                    {
                        outputFile.WriteLine(des.Decrypt(line, textBox2.Text));
                    }
                }
            }
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }
    }
}
