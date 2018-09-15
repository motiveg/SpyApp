import UIKit

class SpyAppViewController: UIViewController, UITextFieldDelegate {

    @IBOutlet weak var input: UITextField!
    @IBOutlet weak var secret: UITextField!
    @IBOutlet weak var cipherSegmentedControl: UISegmentedControl!
    @IBOutlet weak var encodeButton: UIButton!
    @IBOutlet weak var decryptButton: UIButton!
    @IBOutlet weak var clearButton: UIButton!
    @IBOutlet weak var output: UILabel!
    @IBOutlet weak var copyButton: UIButton!
    
    let factory = CipherFactory()
    var cipher: Cipher!
    
    override func viewDidLoad() {

        super.viewDidLoad()

        // control styling
        cipherSegmentedControl.layer.cornerRadius = 10.0
        cipherSegmentedControl.layer.borderWidth = 1.0
        cipherSegmentedControl.layer.masksToBounds = true
        encodeButton.layer.cornerRadius = 10.0
        decryptButton.layer.cornerRadius = 10.0
        clearButton.layer.cornerRadius = 10.0
        copyButton.layer.cornerRadius = 10.0
        
        // initialize segment selection
        let segmentIndex = 0
        let key = cipherSegmentedControl.titleForSegment(at: segmentIndex)
        cipher = factory.cipher(for: key!)

        //output.sizeToFit()
    }
    
    @IBAction func cipherSegmentSelected(_ sender: UISegmentedControl) {
        let segmentIndex = cipherSegmentedControl.selectedSegmentIndex
        let key = cipherSegmentedControl.titleForSegment(at: segmentIndex)
        cipher = factory.cipher(for: key!)
    }

    @IBAction func encodeButtonPressed(_ sender: UIButton) {
        output.text = "" // clear output first
        let plaintext = input.text!
        let secret = self.secret.text!
        
        if (plaintext == "") {
            output.text = "No message entered.\n"
        }
        if (secret == "") {
            output.text = output.text! + "No secret entered.\n"
        }
        if (plaintext != "" && secret != "") {
            output.text = cipher.encode(plaintext, secret: secret)
        }
    }
    
    @IBAction func decryptButtonPressed(_ sender: UIButton) {
        output.text = "" // clear output first
        let plaintext = input.text!
        let secret = self.secret.text!
        
        if (plaintext == "") {
            output.text = "No message entered.\n"
        }
        if (secret == "") {
            output.text = output.text! + "No secret entered.\n"
        }
        if (plaintext != "" && secret != "") {
            output.text = cipher.decrypt(plaintext, secret: secret)
        }
    }

    @IBAction func clearButtonPressed(_ sender: UIButton) {
        input.text = ""
        secret.text = ""
        output.text = ""
        view.endEditing(true)
    }

    @IBAction func onTap(_ sender: Any) {
        view.endEditing(true)
    }
    
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        input.resignFirstResponder()
        return true
    }
    
    @IBAction func copyButtonPressed(_ sender: UIButton) {
        UIPasteboard.general.string = output.text
    }
    
    
}

