const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// MongoDB 连接字符串
const mongoURI = 'mongodb://your_mongodb_connection_string';

// 连接到 MongoDB
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// 定义一个示例 Schema 和 Model
const ItemSchema = new mongoose.Schema({
  name: String,
  quantity: Number
});

const Item = mongoose.model('Item', ItemSchema);

// 获取所有项目
app.get('/items', async (req, res) => {
  try {
    const items = await Item.find();
    res.json(items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 创建一个新项目
app.post('/items', async (req, res) => {
  const item = new Item({
    name: req.body.name,
    quantity: req.body.quantity
  });

  try {
    const newItem = await item.save();
    res.status(201).json(newItem);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// 设置服务器端口
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
